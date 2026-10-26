// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
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
	s53 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s53"
	s54 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s54"
	s55 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s55"
	s56 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s56"
	s57 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s57"
	s58 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s58"
	s59 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s59"
	s60 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s60"
	s61 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s61"
	s64 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s64"
	s65 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s65"
	s66 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s66"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	testing "testing"
)

func tAIItemIEFieldFreshMust(v s42.TAIItemIEField, err error) s42.TAIItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func tAIItemIEValueERABIEContainerListAPERValueFreshMust(v s42.TAIItemIEValueERABIEContainerListAPERValue, err error) s42.TAIItemIEValueERABIEContainerListAPERValue {
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
func tAIItemIEFieldAPERValueFreshMust(v s42.TAIItemIEFieldAPERValue, err error) s42.TAIItemIEFieldAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
func criticalityDiagnosticsExtIEsExtFieldFreshMust(v s09.CriticalityDiagnosticsExtIEsExtField, err error) s09.CriticalityDiagnosticsExtIEsExtField {
	if err != nil {
		panic(err)
	}
	return v
}
func criticalityDiagnosticsExtIEsExtContainerAPERValueFreshMust(v s09.CriticalityDiagnosticsExtIEsExtContainerAPERValue, err error) s09.CriticalityDiagnosticsExtIEsExtContainerAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
func privateIEIDFreshMust(v s23.PrivateIEID,

	err error) s23.PrivateIEID {
	if err != nil {
		panic(err)
	}
	return v
}
func privateMessageIEsValuePrivateIEFieldFreshMust(v s29.PrivateMessageIEsValuePrivateIEField, err error) s29.PrivateMessageIEsValuePrivateIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func privateMessageIEsValuePrivateIEContainerAPERValueFreshMust(v s29.PrivateMessageIEsValuePrivateIEContainerAPERValue, err error) s29.PrivateMessageIEsValuePrivateIEContainerAPERValue {
	if err != nil {
		panic(err)
	}
	return v
}
func errorIndicationIEFieldConsistencyMust(value s36.ErrorIndicationIEField, err error) s36.ErrorIndicationIEField {
	if err != nil {
		panic(err)
	}
	return value
}
func eRABInformationListItemExtIEsExtFieldConsistencyMust(value s37.ERABInformationListItemExtIEsExtField, err error) s37.ERABInformationListItemExtIEsExtField {
	if err != nil {
		panic(err)
	}
	return value
}
func criticalityDiagnosticsExtIEsExtFieldConsistencyMust(value s09.CriticalityDiagnosticsExtIEsExtField, err error) s09.CriticalityDiagnosticsExtIEsExtField {
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
func errorIndicationIEFieldAPERValueConsistencyMust(value s36.ErrorIndicationIEFieldAPERValue, err error) s36.ErrorIndicationIEFieldAPERValue {
	if err != nil {
		panic(err)
	}
	return value
}
func eRABInformationListItemExtIEsExtFieldAPERValueConsistencyMust(value s37.ERABInformationListItemExtIEsExtFieldAPERValue, err error) s37.ERABInformationListItemExtIEsExtFieldAPERValue {
	if err != nil {
		panic(err)
	}
	return value
}
func resetAcknowledgeEnvelopeMust(v s55.ResetAcknowledge,

	err error) s55.ResetAcknowledge {
	if err != nil {
		panic(err)
	}
	return v
}
func causeEnvelopeMust(v s17.Cause,

	err error) s17.Cause {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupFailureEnvelopeMust(v s31.S1SetupFailure,

	err error) s31.S1SetupFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupFailureIEFieldEnvelopeMust(v s27.S1SetupFailureIEField, err error) s27.S1SetupFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func initiatingMessageEnvelopeMust(v s65.InitiatingMessage,

	err error) s65.InitiatingMessage {
	if err != nil {
		panic(err)
	}
	return v
}
func errorIndicationEnvelopeMust(v s36.ErrorIndication,

	err error) s36.ErrorIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func successfulOutcomeEnvelopeMust(v s64.SuccessfulOutcome,

	err error) s64.SuccessfulOutcome {
	if err != nil {
		panic(err)
	}
	return v
}
func unsuccessfulOutcomeEnvelopeMust(v s46.UnsuccessfulOutcome,

	err error) s46.UnsuccessfulOutcome {
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
func privateIEIDEnvelopeMust(v s23.PrivateIEID,

	err error) s23.PrivateIEID {
	if err != nil {
		panic(err)
	}
	return v
}
func privateMessageIEsValuePrivateIEFieldEnvelopeMust(v s29.PrivateMessageIEsValuePrivateIEField, err error) s29.PrivateMessageIEsValuePrivateIEField {
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
func s1APPDUFreshMust(v s66.S1APPDU,

	err error) s66.S1APPDU {
	if err != nil {
		panic(err)
	}
	return v
}
func initiatingMessageFreshMust(v s65.InitiatingMessage,

	err error) s65.InitiatingMessage {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverRequiredFreshMust(v s43.HandoverRequired,

	err error) s43.HandoverRequired {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverRequiredIEFieldFreshMust(v s43.HandoverRequiredIEField, err error) s43.HandoverRequiredIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func causeFreshMust(v s17.Cause,

	err error) s17.Cause {
	if err != nil {
		panic(err)
	}
	return v
}
func targetIDFreshMust(v s43.TargetID,

	err error) s43.TargetID {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBIDFreshMust(v s18.ENBID,

	err error) s18.ENBID {
	if err != nil {
		panic(err)
	}
	return v
}
func successfulOutcomeFreshMust(v s64.SuccessfulOutcome,

	err error) s64.SuccessfulOutcome {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverCommandFreshMust(v s50.HandoverCommand,

	err error) s50.HandoverCommand {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverCommandIEFieldFreshMust(v s50.HandoverCommandIEField, err error) s50.HandoverCommandIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func unsuccessfulOutcomeFreshMust(v s46.UnsuccessfulOutcome,

	err error) s46.UnsuccessfulOutcome {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverPreparationFailureFreshMust(v s29.HandoverPreparationFailure,

	err error) s29.HandoverPreparationFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverPreparationFailureIEFieldFreshMust(v s26.HandoverPreparationFailureIEField, err error) s26.HandoverPreparationFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverRequestFreshMust(v s60.HandoverRequest,

	err error) s60.HandoverRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverRequestIEFieldFreshMust(v s59.HandoverRequestIEField, err error) s59.HandoverRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABToBeSetupItemHOReqIEFieldFreshMust(v s38.ERABToBeSetupItemHOReqIEField, err error) s38.ERABToBeSetupItemHOReqIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverRequestAcknowledgeFreshMust(v s49.HandoverRequestAcknowledge,

	err error) s49.HandoverRequestAcknowledge {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverRequestAcknowledgeIEFieldFreshMust(v s49.HandoverRequestAcknowledgeIEField, err error) s49.HandoverRequestAcknowledgeIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABAdmittedItemIEFieldFreshMust(v s18.ERABAdmittedItemIEField, err error) s18.ERABAdmittedItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverFailureFreshMust(v s29.HandoverFailure,

	err error) s29.HandoverFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverFailureIEFieldFreshMust(v s26.HandoverFailureIEField, err error) s26.HandoverFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func pathSwitchRequestFreshMust(v s51.PathSwitchRequest,

	err error) s51.PathSwitchRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func pathSwitchRequestIEFieldFreshMust(v s51.PathSwitchRequestIEField, err error) s51.PathSwitchRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABToBeSwitchedDLItemIEFieldFreshMust(v s38.ERABToBeSwitchedDLItemIEField, err error) s38.ERABToBeSwitchedDLItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func pathSwitchRequestAcknowledgeFreshMust(v s58.PathSwitchRequestAcknowledge,

	err error) s58.PathSwitchRequestAcknowledge {
	if err != nil {
		panic(err)
	}
	return v
}
func pathSwitchRequestAcknowledgeIEFieldFreshMust(v s58.PathSwitchRequestAcknowledgeIEField, err error) s58.PathSwitchRequestAcknowledgeIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func pathSwitchRequestFailureFreshMust(v s30.PathSwitchRequestFailure,

	err error) s30.PathSwitchRequestFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func pathSwitchRequestFailureIEFieldFreshMust(v s27.PathSwitchRequestFailureIEField, err error) s27.PathSwitchRequestFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABSetupRequestFreshMust(v s51.ERABSetupRequest,

	err error) s51.ERABSetupRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABSetupRequestIEFieldFreshMust(v s51.ERABSetupRequestIEField, err error) s51.ERABSetupRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABToBeSetupItemBearerSUReqIEFieldFreshMust(v s38.ERABToBeSetupItemBearerSUReqIEField, err error) s38.ERABToBeSetupItemBearerSUReqIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABSetupResponseFreshMust(v s57.ERABSetupResponse,

	err error) s57.ERABSetupResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABSetupResponseIEFieldFreshMust(v s56.ERABSetupResponseIEField, err error) s56.ERABSetupResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModifyRequestFreshMust(v s51.ERABModifyRequest,

	err error) s51.ERABModifyRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModifyRequestIEFieldFreshMust(v s50.ERABModifyRequestIEField, err error) s50.ERABModifyRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABToBeModifiedItemBearerModReqIEFieldFreshMust(v s29.ERABToBeModifiedItemBearerModReqIEField, err error) s29.ERABToBeModifiedItemBearerModReqIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModifyResponseFreshMust(v s57.ERABModifyResponse,

	err error) s57.ERABModifyResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModifyResponseIEFieldFreshMust(v s56.ERABModifyResponseIEField, err error) s56.ERABModifyResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABReleaseCommandFreshMust(v s49.ERABReleaseCommand,

	err error) s49.ERABReleaseCommand {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABReleaseCommandIEFieldFreshMust(v s49.ERABReleaseCommandIEField, err error) s49.ERABReleaseCommandIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABItemIEFieldFreshMust(v s19.ERABItemIEField, err error) s19.ERABItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABReleaseResponseFreshMust(v s57.ERABReleaseResponse,

	err error) s57.ERABReleaseResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABReleaseResponseIEFieldFreshMust(v s56.ERABReleaseResponseIEField, err error) s56.ERABReleaseResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func initialContextSetupRequestFreshMust(v s60.InitialContextSetupRequest,

	err error) s60.InitialContextSetupRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func initialContextSetupRequestIEFieldFreshMust(v s60.InitialContextSetupRequestIEField, err error) s60.InitialContextSetupRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABToBeSetupItemCtxtSUReqIEFieldFreshMust(v s38.ERABToBeSetupItemCtxtSUReqIEField, err error) s38.ERABToBeSetupItemCtxtSUReqIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func initialContextSetupResponseFreshMust(v s50.InitialContextSetupResponse,

	err error) s50.InitialContextSetupResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func initialContextSetupResponseIEFieldFreshMust(v s50.InitialContextSetupResponseIEField, err error) s50.InitialContextSetupResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABSetupItemCtxtSUResIEFieldFreshMust(v s19.ERABSetupItemCtxtSUResIEField, err error) s19.ERABSetupItemCtxtSUResIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func initialContextSetupFailureFreshMust(v s30.InitialContextSetupFailure,

	err error) s30.InitialContextSetupFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func initialContextSetupFailureIEFieldFreshMust(v s26.InitialContextSetupFailureIEField, err error) s26.InitialContextSetupFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverCancelFreshMust(v s29.HandoverCancel,

	err error) s29.HandoverCancel {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverCancelIEFieldFreshMust(v s21.HandoverCancelIEField, err error) s21.HandoverCancelIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverCancelAcknowledgeFreshMust(v s29.HandoverCancelAcknowledge,

	err error) s29.HandoverCancelAcknowledge {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverCancelAcknowledgeIEFieldFreshMust(v s26.HandoverCancelAcknowledgeIEField, err error) s26.HandoverCancelAcknowledgeIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func killRequestFreshMust(v s42.KillRequest,

	err error) s42.KillRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func killRequestIEFieldFreshMust(v s41.KillRequestIEField, err error) s41.KillRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func killResponseFreshMust(v s42.KillResponse,

	err error) s42.KillResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func killResponseIEFieldFreshMust(v s41.KillResponseIEField, err error) s41.KillResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func resetFreshMust(v s45.Reset,

	err error) s45.Reset {
	if err != nil {
		panic(err)
	}
	return v
}
func resetIEFieldFreshMust(v s45.ResetIEField, err error) s45.ResetIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func resetTypeFreshMust(v s45.ResetType,

	err error) s45.ResetType {
	if err != nil {
		panic(err)
	}
	return v
}
func resetAcknowledgeFreshMust(v s55.ResetAcknowledge,

	err error) s55.ResetAcknowledge {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupRequestFreshMust(v s54.S1SetupRequest,

	err error) s54.S1SetupRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupRequestIEFieldFreshMust(v s54.S1SetupRequestIEField, err error) s54.S1SetupRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupResponseFreshMust(v s54.S1SetupResponse,

	err error) s54.S1SetupResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupResponseIEFieldFreshMust(v s54.S1SetupResponseIEField, err error) s54.S1SetupResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupFailureFreshMust(v s31.S1SetupFailure,

	err error) s31.S1SetupFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func s1SetupFailureIEFieldFreshMust(v s27.S1SetupFailureIEField, err error) s27.S1SetupFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationRequestFreshMust(v s58.UEContextModificationRequest,

	err error) s58.UEContextModificationRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationRequestIEFieldFreshMust(v s58.UEContextModificationRequestIEField, err error) s58.UEContextModificationRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationResponseFreshMust(v s46.UEContextModificationResponse,

	err error) s46.UEContextModificationResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationResponseIEFieldFreshMust(v s27.UEContextModificationResponseIEField, err error) s27.UEContextModificationResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationFailureFreshMust(v s45.UEContextModificationFailure,

	err error) s45.UEContextModificationFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationFailureIEFieldFreshMust(v s27.UEContextModificationFailureIEField, err error) s27.UEContextModificationFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextReleaseCommandFreshMust(v s47.UEContextReleaseCommand,

	err error) s47.UEContextReleaseCommand {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextReleaseCommandIEFieldFreshMust(v s46.UEContextReleaseCommandIEField, err error) s46.UEContextReleaseCommandIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uES1APIDsFreshMust(v s46.UES1APIDs,

	err error) s46.UES1APIDs {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextReleaseCompleteFreshMust(v s57.UEContextReleaseComplete,

	err error) s57.UEContextReleaseComplete {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextReleaseCompleteIEFieldFreshMust(v s56.UEContextReleaseCompleteIEField, err error) s56.UEContextReleaseCompleteIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBConfigurationUpdateFreshMust(v s54.ENBConfigurationUpdate,

	err error) s54.ENBConfigurationUpdate {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBConfigurationUpdateAcknowledgeFreshMust(v s28.ENBConfigurationUpdateAcknowledge,

	err error) s28.ENBConfigurationUpdateAcknowledge {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBConfigurationUpdateFailureFreshMust(v s28.ENBConfigurationUpdateFailure,

	err error) s28.ENBConfigurationUpdateFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBConfigurationUpdateFailureIEFieldFreshMust(v s26.ENBConfigurationUpdateFailureIEField, err error) s26.ENBConfigurationUpdateFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEConfigurationUpdateFreshMust(v s54.MMEConfigurationUpdate,

	err error) s54.MMEConfigurationUpdate {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEConfigurationUpdateAcknowledgeFreshMust(v s30.MMEConfigurationUpdateAcknowledge,

	err error) s30.MMEConfigurationUpdateAcknowledge {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEConfigurationUpdateFailureFreshMust(v s30.MMEConfigurationUpdateFailure,

	err error) s30.MMEConfigurationUpdateFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEConfigurationUpdateFailureIEFieldFreshMust(v s26.MMEConfigurationUpdateFailureIEField, err error) s26.MMEConfigurationUpdateFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func writeReplaceWarningRequestFreshMust(v s64.WriteReplaceWarningRequest,

	err error) s64.WriteReplaceWarningRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func writeReplaceWarningRequestIEFieldFreshMust(v s42.WriteReplaceWarningRequestIEField, err error) s42.WriteReplaceWarningRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func writeReplaceWarningResponseFreshMust(v s64.WriteReplaceWarningResponse,

	err error) s64.WriteReplaceWarningResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func writeReplaceWarningResponseIEFieldFreshMust(v s41.WriteReplaceWarningResponseIEField, err error) s41.WriteReplaceWarningResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverNotifyFreshMust(v s44.HandoverNotify,

	err error) s44.HandoverNotify {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverNotifyIEFieldFreshMust(v s44.HandoverNotifyIEField, err error) s44.HandoverNotifyIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABReleaseIndicationFreshMust(v s57.ERABReleaseIndication,

	err error) s57.ERABReleaseIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABReleaseIndicationIEFieldFreshMust(v s56.ERABReleaseIndicationIEField, err error) s56.ERABReleaseIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func pagingFreshMust(v s61.Paging,

	err error) s61.Paging {
	if err != nil {
		panic(err)
	}
	return v
}
func pagingIEFieldFreshMust(v s61.PagingIEField, err error) s61.PagingIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEPagingIDFreshMust(v s36.UEPagingID,

	err error) s36.UEPagingID {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkNASTransportFreshMust(v s53.DownlinkNASTransport,

	err error) s53.DownlinkNASTransport {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkNASTransportIEFieldFreshMust(v s53.DownlinkNASTransportIEField, err error) s53.DownlinkNASTransportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func initialUEMessageFreshMust(v s45.InitialUEMessage,

	err error) s45.InitialUEMessage {
	if err != nil {
		panic(err)
	}
	return v
}
func initialUEMessageIEFieldFreshMust(v s44.InitialUEMessageIEField, err error) s44.InitialUEMessageIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkNASTransportFreshMust(v s55.UplinkNASTransport,

	err error) s55.UplinkNASTransport {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkNASTransportIEFieldFreshMust(v s41.UplinkNASTransportIEField, err error) s41.UplinkNASTransportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func errorIndicationFreshMust(v s36.ErrorIndication,

	err error) s36.ErrorIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func nASNonDeliveryIndicationFreshMust(v s30.NASNonDeliveryIndication,

	err error) s30.NASNonDeliveryIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func nASNonDeliveryIndicationIEFieldFreshMust(v s22.NASNonDeliveryIndicationIEField, err error) s22.NASNonDeliveryIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextReleaseRequestFreshMust(v s53.UEContextReleaseRequest,

	err error) s53.UEContextReleaseRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextReleaseRequestIEFieldFreshMust(v s53.UEContextReleaseRequestIEField, err error) s53.UEContextReleaseRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkS1cdma2000tunnellingFreshMust(v s50.DownlinkS1cdma2000tunnelling,

	err error) s50.DownlinkS1cdma2000tunnelling {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkS1cdma2000tunnellingIEFieldFreshMust(v s50.DownlinkS1cdma2000tunnellingIEField, err error) s50.DownlinkS1cdma2000tunnellingIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkS1cdma2000tunnellingFreshMust(v s55.UplinkS1cdma2000tunnelling,

	err error) s55.UplinkS1cdma2000tunnelling {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkS1cdma2000tunnellingIEFieldFreshMust(v s24.UplinkS1cdma2000tunnellingIEField, err error) s24.UplinkS1cdma2000tunnellingIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uECapabilityInfoIndicationFreshMust(v s45.UECapabilityInfoIndication,

	err error) s45.UECapabilityInfoIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func uECapabilityInfoIndicationIEFieldFreshMust(v s14.UECapabilityInfoIndicationIEField, err error) s14.UECapabilityInfoIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBStatusTransferFreshMust(v s28.ENBStatusTransfer,

	err error) s28.ENBStatusTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBStatusTransferIEFieldFreshMust(v s25.ENBStatusTransferIEField, err error) s25.ENBStatusTransferIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func bearersSubjectToStatusTransferItemIEFieldFreshMust(v s25.BearersSubjectToStatusTransferItemIEField, err error) s25.BearersSubjectToStatusTransferItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEStatusTransferFreshMust(v s30.MMEStatusTransfer,

	err error) s30.MMEStatusTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEStatusTransferIEFieldFreshMust(v s25.MMEStatusTransferIEField, err error) s25.MMEStatusTransferIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func deactivateTraceFreshMust(v s18.DeactivateTrace,

	err error) s18.DeactivateTrace {
	if err != nil {
		panic(err)
	}
	return v
}
func deactivateTraceIEFieldFreshMust(v s09.DeactivateTraceIEField, err error) s09.DeactivateTraceIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func traceStartFreshMust(v s61.TraceStart,

	err error) s61.TraceStart {
	if err != nil {
		panic(err)
	}
	return v
}
func traceStartIEFieldFreshMust(v s60.TraceStartIEField, err error) s60.TraceStartIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func traceFailureIndicationFreshMust(v s44.TraceFailureIndication,

	err error) s44.TraceFailureIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func traceFailureIndicationIEFieldFreshMust(v s24.TraceFailureIndicationIEField, err error) s24.TraceFailureIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func cellTrafficTraceFreshMust(v s25.CellTrafficTrace,

	err error) s25.CellTrafficTrace {
	if err != nil {
		panic(err)
	}
	return v
}
func cellTrafficTraceIEFieldFreshMust(v s20.CellTrafficTraceIEField, err error) s20.CellTrafficTraceIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func locationReportingControlFreshMust(v s31.LocationReportingControl,

	err error) s31.LocationReportingControl {
	if err != nil {
		panic(err)
	}
	return v
}
func locationReportingControlIEFieldFreshMust(v s31.LocationReportingControlIEField, err error) s31.LocationReportingControlIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func locationReportingFailureIndicationFreshMust(v s30.LocationReportingFailureIndication,

	err error) s30.LocationReportingFailureIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func locationReportingFailureIndicationIEFieldFreshMust(v s22.LocationReportingFailureIndicationIEField, err error) s22.LocationReportingFailureIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func locationReportFreshMust(v s42.LocationReport,

	err error) s42.LocationReport {
	if err != nil {
		panic(err)
	}
	return v
}
func locationReportIEFieldFreshMust(v s40.LocationReportIEField, err error) s40.LocationReportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func overloadStartFreshMust(v s52.OverloadStart,

	err error) s52.OverloadStart {
	if err != nil {
		panic(err)
	}
	return v
}
func overloadStartIEFieldFreshMust(v s51.OverloadStartIEField, err error) s51.OverloadStartIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func overloadResponseFreshMust(v s23.OverloadResponse,

	err error) s23.OverloadResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func overloadStopFreshMust(v s52.OverloadStop,

	err error) s52.OverloadStop {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBDirectInformationTransferFreshMust(v s43.ENBDirectInformationTransfer,

	err error) s43.ENBDirectInformationTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBDirectInformationTransferIEFieldFreshMust(v s43.ENBDirectInformationTransferIEField, err error) s43.ENBDirectInformationTransferIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func interSystemInformationTransferTypeFreshMust(v s43.InterSystemInformationTransferType,

	err error) s43.InterSystemInformationTransferType {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEDirectInformationTransferFreshMust(v s43.MMEDirectInformationTransfer,

	err error) s43.MMEDirectInformationTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEDirectInformationTransferIEFieldFreshMust(v s43.MMEDirectInformationTransferIEField, err error) s43.MMEDirectInformationTransferIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBConfigurationTransferFreshMust(v s65.ENBConfigurationTransfer,

	err error) s65.ENBConfigurationTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEConfigurationTransferFreshMust(v s65.MMEConfigurationTransfer,

	err error) s65.MMEConfigurationTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func privateMessageFreshMust(v s30.PrivateMessage,

	err error) s30.PrivateMessage {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityMatchRequestFreshMust(v s46.UERadioCapabilityMatchRequest,

	err error) s46.UERadioCapabilityMatchRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityMatchRequestIEFieldFreshMust(v s14.UERadioCapabilityMatchRequestIEField, err error) s14.UERadioCapabilityMatchRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityMatchResponseFreshMust(v s46.UERadioCapabilityMatchResponse,

	err error) s46.UERadioCapabilityMatchResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityMatchResponseIEFieldFreshMust(v s28.UERadioCapabilityMatchResponseIEField, err error) s28.UERadioCapabilityMatchResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModificationIndicationFreshMust(v s57.ERABModificationIndication,

	err error) s57.ERABModificationIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModificationIndicationIEFieldFreshMust(v s56.ERABModificationIndicationIEField, err error) s56.ERABModificationIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABToBeModifiedItemBearerModIndIEFieldFreshMust(v s20.ERABToBeModifiedItemBearerModIndIEField, err error) s20.ERABToBeModifiedItemBearerModIndIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModificationConfirmFreshMust(v s49.ERABModificationConfirm,

	err error) s49.ERABModificationConfirm {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABModificationConfirmIEFieldFreshMust(v s49.ERABModificationConfirmIEField, err error) s49.ERABModificationConfirmIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationIndicationFreshMust(v s46.UEContextModificationIndication,

	err error) s46.UEContextModificationIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationIndicationIEFieldFreshMust(v s24.UEContextModificationIndicationIEField, err error) s24.UEContextModificationIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationConfirmFreshMust(v s45.UEContextModificationConfirm,

	err error) s45.UEContextModificationConfirm {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextModificationConfirmIEFieldFreshMust(v s27.UEContextModificationConfirmIEField, err error) s27.UEContextModificationConfirmIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextSuspendRequestFreshMust(v s57.UEContextSuspendRequest,

	err error) s57.UEContextSuspendRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextSuspendRequestIEFieldFreshMust(v s56.UEContextSuspendRequestIEField, err error) s56.UEContextSuspendRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextSuspendResponseFreshMust(v s46.UEContextSuspendResponse,

	err error) s46.UEContextSuspendResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextSuspendResponseIEFieldFreshMust(v s36.UEContextSuspendResponseIEField, err error) s36.UEContextSuspendResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextResumeRequestFreshMust(v s48.UEContextResumeRequest,

	err error) s48.UEContextResumeRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextResumeRequestIEFieldFreshMust(v s48.UEContextResumeRequestIEField, err error) s48.UEContextResumeRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextResumeResponseFreshMust(v s49.UEContextResumeResponse,

	err error) s49.UEContextResumeResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextResumeResponseIEFieldFreshMust(v s48.UEContextResumeResponseIEField, err error) s48.UEContextResumeResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextResumeFailureFreshMust(v s46.UEContextResumeFailure,

	err error) s46.UEContextResumeFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func uEContextResumeFailureIEFieldFreshMust(v s27.UEContextResumeFailureIEField, err error) s27.UEContextResumeFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityIDMappingRequestFreshMust(v s46.UERadioCapabilityIDMappingRequest,

	err error) s46.UERadioCapabilityIDMappingRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityIDMappingRequestIEFieldFreshMust(v s14.UERadioCapabilityIDMappingRequestIEField, err error) s14.UERadioCapabilityIDMappingRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityIDMappingResponseFreshMust(v s46.UERadioCapabilityIDMappingResponse,

	err error) s46.UERadioCapabilityIDMappingResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func uERadioCapabilityIDMappingResponseIEFieldFreshMust(v s28.UERadioCapabilityIDMappingResponseIEField, err error) s28.UERadioCapabilityIDMappingResponseIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func s1RemovalRequestFreshMust(v s31.S1RemovalRequest,

	err error) s31.S1RemovalRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func s1RemovalRequestIEFieldFreshMust(v s24.S1RemovalRequestIEField, err error) s24.S1RemovalRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func s1RemovalResponseFreshMust(v s31.S1RemovalResponse,

	err error) s31.S1RemovalResponse {
	if err != nil {
		panic(err)
	}
	return v
}
func s1RemovalFailureFreshMust(v s31.S1RemovalFailure,

	err error) s31.S1RemovalFailure {
	if err != nil {
		panic(err)
	}
	return v
}
func s1RemovalFailureIEFieldFreshMust(v s27.S1RemovalFailureIEField, err error) s27.S1RemovalFailureIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkUEAssociatedLPPaTransportFreshMust(v s18.DownlinkUEAssociatedLPPaTransport,

	err error) s18.DownlinkUEAssociatedLPPaTransport {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkUEAssociatedLPPaTransportIEFieldFreshMust(v s09.DownlinkUEAssociatedLPPaTransportIEField, err error) s09.DownlinkUEAssociatedLPPaTransportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkUEAssociatedLPPaTransportFreshMust(v s55.UplinkUEAssociatedLPPaTransport,

	err error) s55.UplinkUEAssociatedLPPaTransport {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkUEAssociatedLPPaTransportIEFieldFreshMust(v s14.UplinkUEAssociatedLPPaTransportIEField, err error) s14.UplinkUEAssociatedLPPaTransportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkNonUEAssociatedLPPaTransportFreshMust(v s18.DownlinkNonUEAssociatedLPPaTransport,

	err error) s18.DownlinkNonUEAssociatedLPPaTransport {
	if err != nil {
		panic(err)
	}
	return v
}
func downlinkNonUEAssociatedLPPaTransportIEFieldFreshMust(v s09.DownlinkNonUEAssociatedLPPaTransportIEField, err error) s09.DownlinkNonUEAssociatedLPPaTransportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkNonUEAssociatedLPPaTransportFreshMust(v s55.UplinkNonUEAssociatedLPPaTransport,

	err error) s55.UplinkNonUEAssociatedLPPaTransport {
	if err != nil {
		panic(err)
	}
	return v
}
func uplinkNonUEAssociatedLPPaTransportIEFieldFreshMust(v s14.UplinkNonUEAssociatedLPPaTransportIEField, err error) s14.UplinkNonUEAssociatedLPPaTransportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func pWSRestartIndicationFreshMust(v s55.PWSRestartIndication,

	err error) s55.PWSRestartIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func pWSRestartIndicationIEFieldFreshMust(v s55.PWSRestartIndicationIEField, err error) s55.PWSRestartIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func rerouteNASRequestFreshMust(v s31.RerouteNASRequest,

	err error) s31.RerouteNASRequest {
	if err != nil {
		panic(err)
	}
	return v
}
func rerouteNASRequestIEFieldFreshMust(v s23.RerouteNASRequestIEField, err error) s23.RerouteNASRequestIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func pWSFailureIndicationFreshMust(v s52.PWSFailureIndication,

	err error) s52.PWSFailureIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func pWSFailureIndicationIEFieldFreshMust(v s52.PWSFailureIndicationIEField, err error) s52.PWSFailureIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func connectionEstablishmentIndicationFreshMust(v s40.ConnectionEstablishmentIndication,

	err error) s40.ConnectionEstablishmentIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func connectionEstablishmentIndicationIEFieldFreshMust(v s39.ConnectionEstablishmentIndicationIEField, err error) s39.ConnectionEstablishmentIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func nASDeliveryIndicationFreshMust(v s22.NASDeliveryIndication,

	err error) s22.NASDeliveryIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func nASDeliveryIndicationIEFieldFreshMust(v s12.NASDeliveryIndicationIEField, err error) s12.NASDeliveryIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func retrieveUEInformationFreshMust(v s36.RetrieveUEInformation,

	err error) s36.RetrieveUEInformation {
	if err != nil {
		panic(err)
	}
	return v
}
func retrieveUEInformationIEFieldFreshMust(v s36.RetrieveUEInformationIEField, err error) s36.RetrieveUEInformationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func uEInformationTransferFreshMust(v s46.UEInformationTransfer,

	err error) s46.UEInformationTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func uEInformationTransferIEFieldFreshMust(v s39.UEInformationTransferIEField, err error) s39.UEInformationTransferIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBCPRelocationIndicationFreshMust(v s47.ENBCPRelocationIndication,

	err error) s47.ENBCPRelocationIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBCPRelocationIndicationIEFieldFreshMust(v s47.ENBCPRelocationIndicationIEField, err error) s47.ENBCPRelocationIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func mMECPRelocationIndicationFreshMust(v s22.MMECPRelocationIndication,

	err error) s22.MMECPRelocationIndication {
	if err != nil {
		panic(err)
	}
	return v
}
func mMECPRelocationIndicationIEFieldFreshMust(v s11.MMECPRelocationIndicationIEField, err error) s11.MMECPRelocationIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func secondaryRATDataUsageReportFreshMust(v s57.SecondaryRATDataUsageReport,

	err error) s57.SecondaryRATDataUsageReport {
	if err != nil {
		panic(err)
	}
	return v
}
func secondaryRATDataUsageReportIEFieldFreshMust(v s56.SecondaryRATDataUsageReportIEField, err error) s56.SecondaryRATDataUsageReportIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func secondaryRATDataUsageReportItemIEFieldFreshMust(v s36.SecondaryRATDataUsageReportItemIEField, err error) s36.SecondaryRATDataUsageReportItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eRABUsageReportItemIEFieldFreshMust(v s20.ERABUsageReportItemIEField, err error) s20.ERABUsageReportItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverSuccessFreshMust(v s21.HandoverSuccess,

	err error) s21.HandoverSuccess {
	if err != nil {
		panic(err)
	}
	return v
}
func handoverSuccessIEFieldFreshMust(v s11.HandoverSuccessIEField, err error) s11.HandoverSuccessIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBEarlyStatusTransferFreshMust(v s47.ENBEarlyStatusTransfer,

	err error) s47.ENBEarlyStatusTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func eNBEarlyStatusTransferIEFieldFreshMust(v s47.ENBEarlyStatusTransferIEField, err error) s47.ENBEarlyStatusTransferIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func bearersSubjectToEarlyStatusTransferItemIEFieldFreshMust(v s17.BearersSubjectToEarlyStatusTransferItemIEField, err error) s17.BearersSubjectToEarlyStatusTransferItemIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func dLCOUNTPDCPSNlengthFreshMust(v s17.DLCOUNTPDCPSNlength,

	err error) s17.DLCOUNTPDCPSNlength {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEEarlyStatusTransferFreshMust(v s48.MMEEarlyStatusTransfer,

	err error) s48.MMEEarlyStatusTransfer {
	if err != nil {
		panic(err)
	}
	return v
}
func mMEEarlyStatusTransferIEFieldFreshMust(v s47.MMEEarlyStatusTransferIEField, err error) s47.MMEEarlyStatusTransferIEField {
	if err != nil {
		panic(err)
	}
	return v
}
func privateMessageIEsValuePrivateIEFieldAPERValueFreshMust(v s29.PrivateMessageIEsValuePrivateIEFieldAPERValue, err error) s29.PrivateMessageIEsValuePrivateIEFieldAPERValue {
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
func errorIndicationIEFieldFreshMust(v s36.ErrorIndicationIEField, err error) s36.ErrorIndicationIEField {
	if err != nil {
		panic(err)
	}
	return v
}

type ErrorIndicationSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s36.ErrorIndication, aper.DecodeState,

	) (s36.ErrorIndication, aper.Snapshot,

	)
	compare func(s36.ErrorIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s36.ErrorIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s36.ErrorIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s36.ErrorIndication,

		error)
	inject func(s36.ErrorIndication,

	) s64.SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ErrorIndicationSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ErrorIndicationSuccessfulBinding) Codec() s36.ErrorIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.ErrorIndicationValueCodec{}
	}
	return func() s36.ErrorIndicationValueCodec {
		sealed := s36.ErrorIndicationValueCodec{}
		*s36.BridgeErrorIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s36.BridgeErrorIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s36.BridgeErrorIndicationValueCodecFieldEncode(&sealed) = func(value s36.ErrorIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s36.BridgeErrorIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s36.BridgeErrorIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s36.BridgeErrorIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ErrorIndicationSuccessfulBinding) Build(body s36.ErrorIndication,

	options ...aper.BuildOption) (s64.SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s64.SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s64.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s64.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s64.SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s64.SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s64.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s64.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return s64.SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

type ErrorIndicationUnsuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s36.ErrorIndication, aper.DecodeState,

	) (s36.ErrorIndication, aper.Snapshot,

	)
	compare func(s36.ErrorIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s36.ErrorIndication,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s36.ErrorIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s36.ErrorIndication,

		error)
	inject func(s36.ErrorIndication,

	) s46.UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ErrorIndicationUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ErrorIndicationUnsuccessfulBinding) Codec() s36.ErrorIndicationValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.ErrorIndicationValueCodec{}
	}
	return func() s36.ErrorIndicationValueCodec {
		sealed := s36.ErrorIndicationValueCodec{}
		*s36.BridgeErrorIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s36.BridgeErrorIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s36.BridgeErrorIndicationValueCodecFieldEncode(&sealed) = func(value s36.ErrorIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s36.BridgeErrorIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s36.BridgeErrorIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s36.BridgeErrorIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ErrorIndicationUnsuccessfulBinding) Build(body s36.ErrorIndication,

	options ...aper.BuildOption) (s46.UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.UnsuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s46.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s46.UnsuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.UnsuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s46.UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s46.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return s46.UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
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
func tAIItemIEContainerAPERValueFreshMust(v s42.TAIItemIEContainerAPERValue, err error) s42.TAIItemIEContainerAPERValue {
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
func criticalityDiagnosticsCheckFreshCodec(t *testing.T, codec s26.CriticalityDiagnosticsValueCodec, wire, preferred []byte) {
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
func cellTrafficTraceIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s20.CellTrafficTraceIEField) {
	t.Helper()
	zero := s20.CellTrafficTraceIEField{Id: 0, Criticality: selected.Criticality}
	report := s32.BridgeCellTrafficTraceIEValueValidateS1APIEContainer(s20.CellTrafficTraceIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s20.BridgeCellTrafficTraceIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s20.CellTrafficTraceIEField{selected, opaque} {
		if !s20.BridgeCellTrafficTraceIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s20.BridgeCellTrafficTraceIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func connectionEstablishmentIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s39.ConnectionEstablishmentIndicationIEField) {
	t.Helper()
	zero := s39.ConnectionEstablishmentIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s40.BridgeConnectionEstablishmentIndicationIEValueValidateS1APIEContainer(s39.ConnectionEstablishmentIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s39.BridgeConnectionEstablishmentIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s39.ConnectionEstablishmentIndicationIEField{selected, opaque} {
		if !s39.BridgeConnectionEstablishmentIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s39.BridgeConnectionEstablishmentIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func deactivateTraceIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s09.DeactivateTraceIEField) {
	t.Helper()
	zero := s09.DeactivateTraceIEField{Id: 0, Criticality: selected.Criticality}
	report := s32.BridgeDeactivateTraceIEValueValidateS1APIEContainer(s09.DeactivateTraceIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s09.BridgeDeactivateTraceIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s09.DeactivateTraceIEField{selected, opaque} {
		if !s09.BridgeDeactivateTraceIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s09.BridgeDeactivateTraceIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func downlinkNASTransportIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s53.DownlinkNASTransportIEField) {
	t.Helper()
	zero := s53.DownlinkNASTransportIEField{Id: 0, Criticality: selected.Criticality}
	report := s53.BridgeDownlinkNASTransportIEValueValidateS1APIEContainer(s53.DownlinkNASTransportIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s53.BridgeDownlinkNASTransportIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s53.DownlinkNASTransportIEField{selected, opaque} {
		if !s53.BridgeDownlinkNASTransportIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s53.BridgeDownlinkNASTransportIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func downlinkS1cdma2000tunnellingIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s50.DownlinkS1cdma2000tunnellingIEField) {
	t.Helper()
	zero := s50.DownlinkS1cdma2000tunnellingIEField{Id: 0, Criticality: selected.Criticality}
	report := s50.BridgeDownlinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(s50.DownlinkS1cdma2000tunnellingIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s50.BridgeDownlinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s50.DownlinkS1cdma2000tunnellingIEField{selected, opaque} {
		if !s50.BridgeDownlinkS1cdma2000tunnellingIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s50.BridgeDownlinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func downlinkUEAssociatedLPPaTransportIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s09.DownlinkUEAssociatedLPPaTransportIEField) {
	t.Helper()
	zero := s09.DownlinkUEAssociatedLPPaTransportIEField{Id: 0, Criticality: selected.Criticality}
	report := s32.BridgeDownlinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(s09.DownlinkUEAssociatedLPPaTransportIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s09.DownlinkUEAssociatedLPPaTransportIEField{selected, opaque} {
		if !s09.BridgeDownlinkUEAssociatedLPPaTransportIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s09.BridgeDownlinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABModificationConfirmIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s49.ERABModificationConfirmIEField) {
	t.Helper()
	zero := s49.ERABModificationConfirmIEField{Id: 0, Criticality: selected.Criticality}
	report := s49.BridgeERABModificationConfirmIEValueValidateS1APIEContainer(s49.ERABModificationConfirmIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s49.BridgeERABModificationConfirmIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s49.ERABModificationConfirmIEField{selected, opaque} {
		if !s49.BridgeERABModificationConfirmIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s49.BridgeERABModificationConfirmIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABModificationIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s56.ERABModificationIndicationIEField) {
	t.Helper()
	zero := s56.ERABModificationIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s57.BridgeERABModificationIndicationIEValueValidateS1APIEContainer(s56.ERABModificationIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s56.BridgeERABModificationIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s56.ERABModificationIndicationIEField{selected, opaque} {
		if !s56.BridgeERABModificationIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s56.BridgeERABModificationIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABModifyRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s50.ERABModifyRequestIEField) {
	t.Helper()
	zero := s50.ERABModifyRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s51.BridgeERABModifyRequestIEValueValidateS1APIEContainer(s50.ERABModifyRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s50.BridgeERABModifyRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s50.ERABModifyRequestIEField{selected, opaque} {
		if !s50.BridgeERABModifyRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s50.BridgeERABModifyRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABModifyResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s56.ERABModifyResponseIEField) {
	t.Helper()
	zero := s56.ERABModifyResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s57.BridgeERABModifyResponseIEValueValidateS1APIEContainer(s56.ERABModifyResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s56.BridgeERABModifyResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s56.ERABModifyResponseIEField{selected, opaque} {
		if !s56.BridgeERABModifyResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s56.BridgeERABModifyResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABReleaseCommandIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s49.ERABReleaseCommandIEField) {
	t.Helper()
	zero := s49.ERABReleaseCommandIEField{Id: 0, Criticality: selected.Criticality}
	report := s49.BridgeERABReleaseCommandIEValueValidateS1APIEContainer(s49.ERABReleaseCommandIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s49.BridgeERABReleaseCommandIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s49.ERABReleaseCommandIEField{selected, opaque} {
		if !s49.BridgeERABReleaseCommandIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s49.BridgeERABReleaseCommandIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABReleaseIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s56.ERABReleaseIndicationIEField) {
	t.Helper()
	zero := s56.ERABReleaseIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s57.BridgeERABReleaseIndicationIEValueValidateS1APIEContainer(s56.ERABReleaseIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s56.BridgeERABReleaseIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s56.ERABReleaseIndicationIEField{selected, opaque} {
		if !s56.BridgeERABReleaseIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s56.BridgeERABReleaseIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABReleaseResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s56.ERABReleaseResponseIEField) {
	t.Helper()
	zero := s56.ERABReleaseResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s57.BridgeERABReleaseResponseIEValueValidateS1APIEContainer(s56.ERABReleaseResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s56.BridgeERABReleaseResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s56.ERABReleaseResponseIEField{selected, opaque} {
		if !s56.BridgeERABReleaseResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s56.BridgeERABReleaseResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABSetupRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s51.ERABSetupRequestIEField) {
	t.Helper()
	zero := s51.ERABSetupRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s51.BridgeERABSetupRequestIEValueValidateS1APIEContainer(s51.ERABSetupRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s51.BridgeERABSetupRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s51.ERABSetupRequestIEField{selected, opaque} {
		if !s51.BridgeERABSetupRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s51.BridgeERABSetupRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eRABSetupResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s56.ERABSetupResponseIEField) {
	t.Helper()
	zero := s56.ERABSetupResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s57.BridgeERABSetupResponseIEValueValidateS1APIEContainer(s56.ERABSetupResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s56.BridgeERABSetupResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s56.ERABSetupResponseIEField{selected, opaque} {
		if !s56.BridgeERABSetupResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s56.BridgeERABSetupResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eNBEarlyStatusTransferIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s47.ENBEarlyStatusTransferIEField) {
	t.Helper()
	zero := s47.ENBEarlyStatusTransferIEField{Id: 0, Criticality: selected.Criticality}
	report := s47.BridgeENBEarlyStatusTransferIEValueValidateS1APIEContainer(s47.ENBEarlyStatusTransferIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s47.BridgeENBEarlyStatusTransferIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s47.ENBEarlyStatusTransferIEField{selected, opaque} {
		if !s47.BridgeENBEarlyStatusTransferIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s47.BridgeENBEarlyStatusTransferIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func eNBStatusTransferIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s25.ENBStatusTransferIEField) {
	t.Helper()
	zero := s25.ENBStatusTransferIEField{Id: 0, Criticality: selected.Criticality}
	report := s32.BridgeENBStatusTransferIEValueValidateS1APIEContainer(s25.ENBStatusTransferIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s25.BridgeENBStatusTransferIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s25.ENBStatusTransferIEField{selected, opaque} {
		if !s25.BridgeENBStatusTransferIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s25.BridgeENBStatusTransferIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func errorIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s36.ErrorIndicationIEField) {
	t.Helper()
	zero := s36.ErrorIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s36.BridgeErrorIndicationIEValueValidateS1APIEContainer(s36.ErrorIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s36.BridgeErrorIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s36.ErrorIndicationIEField{selected, opaque} {
		if !s36.BridgeErrorIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s36.BridgeErrorIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverCancelAcknowledgeIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s26.HandoverCancelAcknowledgeIEField) {
	t.Helper()
	zero := s26.HandoverCancelAcknowledgeIEField{Id: 0, Criticality: selected.Criticality}
	report := s34.BridgeHandoverCancelAcknowledgeIEValueValidateS1APIEContainer(s26.HandoverCancelAcknowledgeIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s26.BridgeHandoverCancelAcknowledgeIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s26.HandoverCancelAcknowledgeIEField{selected, opaque} {
		if !s26.BridgeHandoverCancelAcknowledgeIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s26.BridgeHandoverCancelAcknowledgeIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverCancelIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s21.HandoverCancelIEField) {
	t.Helper()
	zero := s21.HandoverCancelIEField{Id: 0, Criticality: selected.Criticality}
	report := s34.BridgeHandoverCancelIEValueValidateS1APIEContainer(s21.HandoverCancelIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s21.BridgeHandoverCancelIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s21.HandoverCancelIEField{selected, opaque} {
		if !s21.BridgeHandoverCancelIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s21.BridgeHandoverCancelIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverCommandIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s50.HandoverCommandIEField) {
	t.Helper()
	zero := s50.HandoverCommandIEField{Id: 0, Criticality: selected.Criticality}
	report := s50.BridgeHandoverCommandIEValueValidateS1APIEContainer(s50.HandoverCommandIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s50.BridgeHandoverCommandIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s50.HandoverCommandIEField{selected, opaque} {
		if !s50.BridgeHandoverCommandIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s50.BridgeHandoverCommandIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverFailureIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s26.HandoverFailureIEField) {
	t.Helper()
	zero := s26.HandoverFailureIEField{Id: 0, Criticality: selected.Criticality}
	report := s34.BridgeHandoverFailureIEValueValidateS1APIEContainer(s26.HandoverFailureIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s26.BridgeHandoverFailureIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s26.HandoverFailureIEField{selected, opaque} {
		if !s26.BridgeHandoverFailureIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s26.BridgeHandoverFailureIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverNotifyIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s44.HandoverNotifyIEField) {
	t.Helper()
	zero := s44.HandoverNotifyIEField{Id: 0, Criticality: selected.Criticality}
	report := s45.BridgeHandoverNotifyIEValueValidateS1APIEContainer(s44.HandoverNotifyIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s44.BridgeHandoverNotifyIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s44.HandoverNotifyIEField{selected, opaque} {
		if !s44.BridgeHandoverNotifyIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s44.BridgeHandoverNotifyIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverPreparationFailureIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s26.HandoverPreparationFailureIEField) {
	t.Helper()
	zero := s26.HandoverPreparationFailureIEField{Id: 0, Criticality: selected.Criticality}
	report := s34.BridgeHandoverPreparationFailureIEValueValidateS1APIEContainer(s26.HandoverPreparationFailureIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s26.BridgeHandoverPreparationFailureIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s26.HandoverPreparationFailureIEField{selected, opaque} {
		if !s26.BridgeHandoverPreparationFailureIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s26.BridgeHandoverPreparationFailureIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverRequestAcknowledgeIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s49.HandoverRequestAcknowledgeIEField) {
	t.Helper()
	zero := s49.HandoverRequestAcknowledgeIEField{Id: 0, Criticality: selected.Criticality}
	report := s49.BridgeHandoverRequestAcknowledgeIEValueValidateS1APIEContainer(s49.HandoverRequestAcknowledgeIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s49.BridgeHandoverRequestAcknowledgeIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s49.HandoverRequestAcknowledgeIEField{selected, opaque} {
		if !s49.BridgeHandoverRequestAcknowledgeIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s49.BridgeHandoverRequestAcknowledgeIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s59.HandoverRequestIEField) {
	t.Helper()
	zero := s59.HandoverRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s60.BridgeHandoverRequestIEValueValidateS1APIEContainer(s59.HandoverRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s59.BridgeHandoverRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s59.HandoverRequestIEField{selected, opaque} {
		if !s59.BridgeHandoverRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s59.BridgeHandoverRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverRequiredIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s43.HandoverRequiredIEField) {
	t.Helper()
	zero := s43.HandoverRequiredIEField{Id: 0, Criticality: selected.Criticality}
	report := s43.BridgeHandoverRequiredIEValueValidateS1APIEContainer(s43.HandoverRequiredIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s43.BridgeHandoverRequiredIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s43.HandoverRequiredIEField{selected, opaque} {
		if !s43.BridgeHandoverRequiredIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s43.BridgeHandoverRequiredIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func handoverSuccessIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s11.HandoverSuccessIEField) {
	t.Helper()
	zero := s11.HandoverSuccessIEField{Id: 0, Criticality: selected.Criticality}
	report := s34.BridgeHandoverSuccessIEValueValidateS1APIEContainer(s11.HandoverSuccessIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s11.BridgeHandoverSuccessIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s11.HandoverSuccessIEField{selected, opaque} {
		if !s11.BridgeHandoverSuccessIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s11.BridgeHandoverSuccessIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func initialContextSetupFailureIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s26.InitialContextSetupFailureIEField) {
	t.Helper()
	zero := s26.InitialContextSetupFailureIEField{Id: 0, Criticality: selected.Criticality}
	report := s34.BridgeInitialContextSetupFailureIEValueValidateS1APIEContainer(s26.InitialContextSetupFailureIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s26.BridgeInitialContextSetupFailureIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s26.InitialContextSetupFailureIEField{selected, opaque} {
		if !s26.BridgeInitialContextSetupFailureIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s26.BridgeInitialContextSetupFailureIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func initialContextSetupRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s60.InitialContextSetupRequestIEField) {
	t.Helper()
	zero := s60.InitialContextSetupRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s60.BridgeInitialContextSetupRequestIEValueValidateS1APIEContainer(s60.InitialContextSetupRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s60.BridgeInitialContextSetupRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s60.InitialContextSetupRequestIEField{selected, opaque} {
		if !s60.BridgeInitialContextSetupRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s60.BridgeInitialContextSetupRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func initialContextSetupResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s50.InitialContextSetupResponseIEField) {
	t.Helper()
	zero := s50.InitialContextSetupResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s50.BridgeInitialContextSetupResponseIEValueValidateS1APIEContainer(s50.InitialContextSetupResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s50.BridgeInitialContextSetupResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s50.InitialContextSetupResponseIEField{selected, opaque} {
		if !s50.BridgeInitialContextSetupResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s50.BridgeInitialContextSetupResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func locationReportIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s40.LocationReportIEField) {
	t.Helper()
	zero := s40.LocationReportIEField{Id: 0, Criticality: selected.Criticality}
	report := s42.BridgeLocationReportIEValueValidateS1APIEContainer(s40.LocationReportIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s40.BridgeLocationReportIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s40.LocationReportIEField{selected, opaque} {
		if !s40.BridgeLocationReportIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s40.BridgeLocationReportIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func locationReportingControlIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s31.LocationReportingControlIEField) {
	t.Helper()
	zero := s31.LocationReportingControlIEField{Id: 0, Criticality: selected.Criticality}
	report := s34.BridgeLocationReportingControlIEValueValidateS1APIEContainer(s31.LocationReportingControlIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s31.BridgeLocationReportingControlIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s31.LocationReportingControlIEField{selected, opaque} {
		if !s31.BridgeLocationReportingControlIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s31.BridgeLocationReportingControlIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func locationReportingFailureIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s22.LocationReportingFailureIndicationIEField) {
	t.Helper()
	zero := s22.LocationReportingFailureIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s34.BridgeLocationReportingFailureIndicationIEValueValidateS1APIEContainer(s22.LocationReportingFailureIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s22.BridgeLocationReportingFailureIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s22.LocationReportingFailureIndicationIEField{selected, opaque} {
		if !s22.BridgeLocationReportingFailureIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s22.BridgeLocationReportingFailureIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func mMECPRelocationIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s11.MMECPRelocationIndicationIEField) {
	t.Helper()
	zero := s11.MMECPRelocationIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s35.BridgeMMECPRelocationIndicationIEValueValidateS1APIEContainer(s11.MMECPRelocationIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s11.BridgeMMECPRelocationIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s11.MMECPRelocationIndicationIEField{selected, opaque} {
		if !s11.BridgeMMECPRelocationIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s11.BridgeMMECPRelocationIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func mMEEarlyStatusTransferIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s47.MMEEarlyStatusTransferIEField) {
	t.Helper()
	zero := s47.MMEEarlyStatusTransferIEField{Id: 0, Criticality: selected.Criticality}
	report := s48.BridgeMMEEarlyStatusTransferIEValueValidateS1APIEContainer(s47.MMEEarlyStatusTransferIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s47.BridgeMMEEarlyStatusTransferIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s47.MMEEarlyStatusTransferIEField{selected, opaque} {
		if !s47.BridgeMMEEarlyStatusTransferIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s47.BridgeMMEEarlyStatusTransferIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func mMEStatusTransferIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s25.MMEStatusTransferIEField) {
	t.Helper()
	zero := s25.MMEStatusTransferIEField{Id: 0, Criticality: selected.Criticality}
	report := s35.BridgeMMEStatusTransferIEValueValidateS1APIEContainer(s25.MMEStatusTransferIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s25.BridgeMMEStatusTransferIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s25.MMEStatusTransferIEField{selected, opaque} {
		if !s25.BridgeMMEStatusTransferIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s25.BridgeMMEStatusTransferIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func nASDeliveryIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s12.NASDeliveryIndicationIEField) {
	t.Helper()
	zero := s12.NASDeliveryIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s35.BridgeNASDeliveryIndicationIEValueValidateS1APIEContainer(s12.NASDeliveryIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s12.BridgeNASDeliveryIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s12.NASDeliveryIndicationIEField{selected, opaque} {
		if !s12.BridgeNASDeliveryIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s12.BridgeNASDeliveryIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func nASNonDeliveryIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s22.NASNonDeliveryIndicationIEField) {
	t.Helper()
	zero := s22.NASNonDeliveryIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s35.BridgeNASNonDeliveryIndicationIEValueValidateS1APIEContainer(s22.NASNonDeliveryIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s22.BridgeNASNonDeliveryIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s22.NASNonDeliveryIndicationIEField{selected, opaque} {
		if !s22.BridgeNASNonDeliveryIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s22.BridgeNASNonDeliveryIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func pathSwitchRequestAcknowledgeIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s58.PathSwitchRequestAcknowledgeIEField) {
	t.Helper()
	zero := s58.PathSwitchRequestAcknowledgeIEField{Id: 0, Criticality: selected.Criticality}
	report := s58.BridgePathSwitchRequestAcknowledgeIEValueValidateS1APIEContainer(s58.PathSwitchRequestAcknowledgeIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s58.BridgePathSwitchRequestAcknowledgeIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s58.PathSwitchRequestAcknowledgeIEField{selected, opaque} {
		if !s58.BridgePathSwitchRequestAcknowledgeIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s58.BridgePathSwitchRequestAcknowledgeIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func pathSwitchRequestFailureIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s27.PathSwitchRequestFailureIEField) {
	t.Helper()
	zero := s27.PathSwitchRequestFailureIEField{Id: 0, Criticality: selected.Criticality}
	report := s35.BridgePathSwitchRequestFailureIEValueValidateS1APIEContainer(s27.PathSwitchRequestFailureIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s27.BridgePathSwitchRequestFailureIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s27.PathSwitchRequestFailureIEField{selected, opaque} {
		if !s27.BridgePathSwitchRequestFailureIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s27.BridgePathSwitchRequestFailureIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func rerouteNASRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s23.RerouteNASRequestIEField) {
	t.Helper()
	zero := s23.RerouteNASRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s36.BridgeRerouteNASRequestIEValueValidateS1APIEContainer(s23.RerouteNASRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s23.BridgeRerouteNASRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s23.RerouteNASRequestIEField{selected, opaque} {
		if !s23.BridgeRerouteNASRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s23.BridgeRerouteNASRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func secondaryRATDataUsageReportIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s56.SecondaryRATDataUsageReportIEField) {
	t.Helper()
	zero := s56.SecondaryRATDataUsageReportIEField{Id: 0, Criticality: selected.Criticality}
	report := s57.BridgeSecondaryRATDataUsageReportIEValueValidateS1APIEContainer(s56.SecondaryRATDataUsageReportIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s56.BridgeSecondaryRATDataUsageReportIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s56.SecondaryRATDataUsageReportIEField{selected, opaque} {
		if !s56.BridgeSecondaryRATDataUsageReportIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s56.BridgeSecondaryRATDataUsageReportIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func traceFailureIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s24.TraceFailureIndicationIEField) {
	t.Helper()
	zero := s24.TraceFailureIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s44.BridgeTraceFailureIndicationIEValueValidateS1APIEContainer(s24.TraceFailureIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s24.BridgeTraceFailureIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s24.TraceFailureIndicationIEField{selected, opaque} {
		if !s24.BridgeTraceFailureIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s24.BridgeTraceFailureIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func traceStartIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s60.TraceStartIEField) {
	t.Helper()
	zero := s60.TraceStartIEField{Id: 0, Criticality: selected.Criticality}
	report := s61.BridgeTraceStartIEValueValidateS1APIEContainer(s60.TraceStartIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s60.BridgeTraceStartIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s60.TraceStartIEField{selected, opaque} {
		if !s60.BridgeTraceStartIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s60.BridgeTraceStartIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uECapabilityInfoIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s14.UECapabilityInfoIndicationIEField) {
	t.Helper()
	zero := s14.UECapabilityInfoIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s45.BridgeUECapabilityInfoIndicationIEValueValidateS1APIEContainer(s14.UECapabilityInfoIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s14.BridgeUECapabilityInfoIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s14.UECapabilityInfoIndicationIEField{selected, opaque} {
		if !s14.BridgeUECapabilityInfoIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s14.BridgeUECapabilityInfoIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextModificationConfirmIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s27.UEContextModificationConfirmIEField) {
	t.Helper()
	zero := s27.UEContextModificationConfirmIEField{Id: 0, Criticality: selected.Criticality}
	report := s45.BridgeUEContextModificationConfirmIEValueValidateS1APIEContainer(s27.UEContextModificationConfirmIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s27.BridgeUEContextModificationConfirmIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s27.UEContextModificationConfirmIEField{selected, opaque} {
		if !s27.BridgeUEContextModificationConfirmIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s27.BridgeUEContextModificationConfirmIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextModificationFailureIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s27.UEContextModificationFailureIEField) {
	t.Helper()
	zero := s27.UEContextModificationFailureIEField{Id: 0, Criticality: selected.Criticality}
	report := s46.BridgeUEContextModificationFailureIEValueValidateS1APIEContainer(s27.UEContextModificationFailureIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s27.BridgeUEContextModificationFailureIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s27.UEContextModificationFailureIEField{selected, opaque} {
		if !s27.BridgeUEContextModificationFailureIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s27.BridgeUEContextModificationFailureIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextModificationIndicationIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s24.UEContextModificationIndicationIEField) {
	t.Helper()
	zero := s24.UEContextModificationIndicationIEField{Id: 0, Criticality: selected.Criticality}
	report := s46.BridgeUEContextModificationIndicationIEValueValidateS1APIEContainer(s24.UEContextModificationIndicationIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s24.BridgeUEContextModificationIndicationIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s24.UEContextModificationIndicationIEField{selected, opaque} {
		if !s24.BridgeUEContextModificationIndicationIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s24.BridgeUEContextModificationIndicationIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextModificationRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s58.UEContextModificationRequestIEField) {
	t.Helper()
	zero := s58.UEContextModificationRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s58.BridgeUEContextModificationRequestIEValueValidateS1APIEContainer(s58.UEContextModificationRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s58.BridgeUEContextModificationRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s58.UEContextModificationRequestIEField{selected, opaque} {
		if !s58.BridgeUEContextModificationRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s58.BridgeUEContextModificationRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextModificationResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s27.UEContextModificationResponseIEField) {
	t.Helper()
	zero := s27.UEContextModificationResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s46.BridgeUEContextModificationResponseIEValueValidateS1APIEContainer(s27.UEContextModificationResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s27.BridgeUEContextModificationResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s27.UEContextModificationResponseIEField{selected, opaque} {
		if !s27.BridgeUEContextModificationResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s27.BridgeUEContextModificationResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextReleaseCompleteIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s56.UEContextReleaseCompleteIEField) {
	t.Helper()
	zero := s56.UEContextReleaseCompleteIEField{Id: 0, Criticality: selected.Criticality}
	report := s57.BridgeUEContextReleaseCompleteIEValueValidateS1APIEContainer(s56.UEContextReleaseCompleteIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s56.BridgeUEContextReleaseCompleteIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s56.UEContextReleaseCompleteIEField{selected, opaque} {
		if !s56.BridgeUEContextReleaseCompleteIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s56.BridgeUEContextReleaseCompleteIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextReleaseRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s53.UEContextReleaseRequestIEField) {
	t.Helper()
	zero := s53.UEContextReleaseRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s53.BridgeUEContextReleaseRequestIEValueValidateS1APIEContainer(s53.UEContextReleaseRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s53.BridgeUEContextReleaseRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s53.UEContextReleaseRequestIEField{selected, opaque} {
		if !s53.BridgeUEContextReleaseRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s53.BridgeUEContextReleaseRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextResumeFailureIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s27.UEContextResumeFailureIEField) {
	t.Helper()
	zero := s27.UEContextResumeFailureIEField{Id: 0, Criticality: selected.Criticality}
	report := s46.BridgeUEContextResumeFailureIEValueValidateS1APIEContainer(s27.UEContextResumeFailureIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s27.BridgeUEContextResumeFailureIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s27.UEContextResumeFailureIEField{selected, opaque} {
		if !s27.BridgeUEContextResumeFailureIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s27.BridgeUEContextResumeFailureIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextResumeRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s48.UEContextResumeRequestIEField) {
	t.Helper()
	zero := s48.UEContextResumeRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s48.BridgeUEContextResumeRequestIEValueValidateS1APIEContainer(s48.UEContextResumeRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s48.BridgeUEContextResumeRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s48.UEContextResumeRequestIEField{selected, opaque} {
		if !s48.BridgeUEContextResumeRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s48.BridgeUEContextResumeRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextResumeResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s48.UEContextResumeResponseIEField) {
	t.Helper()
	zero := s48.UEContextResumeResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s49.BridgeUEContextResumeResponseIEValueValidateS1APIEContainer(s48.UEContextResumeResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s48.BridgeUEContextResumeResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s48.UEContextResumeResponseIEField{selected, opaque} {
		if !s48.BridgeUEContextResumeResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s48.BridgeUEContextResumeResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextSuspendRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s56.UEContextSuspendRequestIEField) {
	t.Helper()
	zero := s56.UEContextSuspendRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s57.BridgeUEContextSuspendRequestIEValueValidateS1APIEContainer(s56.UEContextSuspendRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s56.BridgeUEContextSuspendRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s56.UEContextSuspendRequestIEField{selected, opaque} {
		if !s56.BridgeUEContextSuspendRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s56.BridgeUEContextSuspendRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uEContextSuspendResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s36.UEContextSuspendResponseIEField) {
	t.Helper()
	zero := s36.UEContextSuspendResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s46.BridgeUEContextSuspendResponseIEValueValidateS1APIEContainer(s36.UEContextSuspendResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s36.BridgeUEContextSuspendResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s36.UEContextSuspendResponseIEField{selected, opaque} {
		if !s36.BridgeUEContextSuspendResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s36.BridgeUEContextSuspendResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uERadioCapabilityMatchRequestIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s14.UERadioCapabilityMatchRequestIEField) {
	t.Helper()
	zero := s14.UERadioCapabilityMatchRequestIEField{Id: 0, Criticality: selected.Criticality}
	report := s46.BridgeUERadioCapabilityMatchRequestIEValueValidateS1APIEContainer(s14.UERadioCapabilityMatchRequestIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s14.BridgeUERadioCapabilityMatchRequestIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s14.UERadioCapabilityMatchRequestIEField{selected, opaque} {
		if !s14.BridgeUERadioCapabilityMatchRequestIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s14.BridgeUERadioCapabilityMatchRequestIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uERadioCapabilityMatchResponseIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s28.UERadioCapabilityMatchResponseIEField) {
	t.Helper()
	zero := s28.UERadioCapabilityMatchResponseIEField{Id: 0, Criticality: selected.Criticality}
	report := s46.BridgeUERadioCapabilityMatchResponseIEValueValidateS1APIEContainer(s28.UERadioCapabilityMatchResponseIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s28.BridgeUERadioCapabilityMatchResponseIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s28.UERadioCapabilityMatchResponseIEField{selected, opaque} {
		if !s28.BridgeUERadioCapabilityMatchResponseIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s28.BridgeUERadioCapabilityMatchResponseIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uplinkNASTransportIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s41.UplinkNASTransportIEField) {
	t.Helper()
	zero := s41.UplinkNASTransportIEField{Id: 0, Criticality: selected.Criticality}
	report := s55.BridgeUplinkNASTransportIEValueValidateS1APIEContainer(s41.UplinkNASTransportIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s41.BridgeUplinkNASTransportIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s41.UplinkNASTransportIEField{selected, opaque} {
		if !s41.BridgeUplinkNASTransportIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s41.BridgeUplinkNASTransportIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uplinkS1cdma2000tunnellingIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s24.UplinkS1cdma2000tunnellingIEField) {
	t.Helper()
	zero := s24.UplinkS1cdma2000tunnellingIEField{Id: 0, Criticality: selected.Criticality}
	report := s55.BridgeUplinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(s24.UplinkS1cdma2000tunnellingIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s24.BridgeUplinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s24.UplinkS1cdma2000tunnellingIEField{selected, opaque} {
		if !s24.BridgeUplinkS1cdma2000tunnellingIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s24.BridgeUplinkS1cdma2000tunnellingIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
			t.Errorf("selected or opaque arm failed: %v", err)
		}
	}
}
func uplinkUEAssociatedLPPaTransportIEValueRequireZeroIDSelection(t *testing.T, selected, opaque s14.UplinkUEAssociatedLPPaTransportIEField) {
	t.Helper()
	zero := s14.UplinkUEAssociatedLPPaTransportIEField{Id: 0, Criticality: selected.Criticality}
	report := s55.BridgeUplinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(s14.UplinkUEAssociatedLPPaTransportIEContainer{zero}, []s00.FieldInfo{{ID: 0, Criticality: selected.Criticality}}, "zero", nil)
	mismatch := false
	for _, issue := range report.Issues {
		mismatch = mismatch || issue.Code == s00.ValueIDMismatch
	}
	if !mismatch {
		t.Error("zero union validated without a selected row")
	}
	bb := aper.NewBitBuffer()
	if err := s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&zero, bb); err == nil {
		t.Error("zero union encoded without a selected row")
	} else if bb.BitPos() != 0 {
		t.Errorf("zero refusal wrote %d bits", bb.BitPos())
	}
	for _, field := range []s14.UplinkUEAssociatedLPPaTransportIEField{selected, opaque} {
		if !s14.BridgeUplinkUEAssociatedLPPaTransportIEValueMethodMatchesID(field.Value, field.Id) {
			t.Errorf("selected or opaque arm refused at id %d", field.Id)
		}
		if err := s14.BridgeUplinkUEAssociatedLPPaTransportIEFieldMethodMarshalAPERTo(&field, aper.NewBitBuffer()); err != nil {
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
