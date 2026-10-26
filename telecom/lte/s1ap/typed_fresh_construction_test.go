// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	hex "encoding/hex"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
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
	s62 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s62"
	s63 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s63"
	s64 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s64"
	s65 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s65"
	s66 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s66"
	s67 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s67"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	big "math/big"
	reflect "reflect"
	testing "testing"
)

// Every procedure body is built from the minimal source-mandatory IE set.
// The goldens come from an independent APER encoder over the locked
// TS 36.413 V19.2.0 §§9.3.2–9.3.4 semantic values.
func TestFreshConstructionAllProcedureBodies(t *testing.T) {
	cases := []struct {
		name, wire string
		build      func() s66.S1APPDU
	}{
		{"HandoverRequired", "0000003000000600000002000000080002000000010001000002400200000004000d000000000000000000000000000068000100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.HandoverPreparationProcedure().Initiating().Build(handoverRequiredFreshMust(s63.NewHandoverRequired(s43.HandoverRequiredIEContainer{handoverRequiredIEFieldFreshMust(s43.HandoverRequiredIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), handoverRequiredIEFieldFreshMust(s43.HandoverRequiredIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), handoverRequiredIEFieldFreshMust(s43.HandoverRequiredIEs().HandoverType().New(s00.HandoverType(0))), handoverRequiredIEFieldFreshMust(s43.HandoverRequiredIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0))))), handoverRequiredIEFieldFreshMust(s43.HandoverRequiredIEs().TargetID().New(targetIDFreshMust(s43.NewTargetIDTargeteNBID(s43.TargeteNBID{GlobalENBID: s21.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: eNBIDFreshMust(s30.NewENBIDMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 20}))}, SelectedTAI: s40.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)}})))), handoverRequiredIEFieldFreshMust(s43.HandoverRequiredIEs().SourceToTargetTransparentContainer().New(make([]byte, 0)))}))))))
		}},
		{"HandoverCommand", "200000190000040000000200000008000200000001000100007b000100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s65.HandoverPreparationProcedure().Successful().Build(handoverCommandFreshMust(s61.NewHandoverCommand(s50.HandoverCommandIEContainer{handoverCommandIEFieldFreshMust(s50.HandoverCommandIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), handoverCommandIEFieldFreshMust(s50.HandoverCommandIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), handoverCommandIEFieldFreshMust(s50.HandoverCommandIEs().HandoverType().New(s00.HandoverType(0))), handoverCommandIEFieldFreshMust(s50.HandoverCommandIEs().TargetToSourceTransparentContainer().New(make([]byte, 0)))}))))))
		}},
		{"HandoverPreparationFailure", "40000015000003000040020000000840020000000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUUnsuccessfulOutcome(unsuccessfulOutcomeFreshMust(s65.HandoverPreparationProcedure().Unsuccessful().Build(handoverPreparationFailureFreshMust(s61.NewHandoverPreparationFailure(s26.HandoverPreparationFailureIEContainer{handoverPreparationFailureIEFieldFreshMust(s26.HandoverPreparationFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), handoverPreparationFailureIEFieldFreshMust(s26.HandoverPreparationFailureIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), handoverPreparationFailureIEFieldFreshMust(s26.HandoverPreparationFailureIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"HandoverRequest", "00010062000008000000020000000100010000024002000000420004000000000035000f00001b000a000000000000000000000068000100006b0005000000000000280021000000000000000000000000000000000000000000000000000000000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.HandoverResourceAllocationProcedure().Initiating().Build(handoverRequestFreshMust(s64.NewHandoverRequest(s59.HandoverRequestIEContainer{handoverRequestIEFieldFreshMust(s60.HandoverRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), handoverRequestIEFieldFreshMust(s60.HandoverRequestIEs().HandoverType().New(s00.HandoverType(0))), handoverRequestIEFieldFreshMust(s60.HandoverRequestIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0))))), handoverRequestIEFieldFreshMust(s60.HandoverRequestIEs().UEaggregateMaximumBitrate().New(s45.UEAggregateMaximumBitrate{UEaggregateMaximumBitRateDL: s00.BitRate(0), UEaggregateMaximumBitRateUL: s00.BitRate(0)})), handoverRequestIEFieldFreshMust(s60.HandoverRequestIEs().ERABToBeSetupListHOReq().New(s38.ERABToBeSetupListHOReq{eRABToBeSetupItemHOReqIEFieldFreshMust(s38.ERABToBeSetupItemHOReqIEs().ERABToBeSetupItemHOReq().New(s38.ERABToBeSetupItemHOReq{ERABID: big.NewInt(0), TransportLayerAddress: runtime.BitString{Bytes: make([]byte, 1), BitLength: 1}, GTPTEID: make([]byte, 4), ERABlevelQosParameters: s21.ERABLevelQoSParameters{QCI: s00.QCI(0), AllocationRetentionPriority: s16.AllocationAndRetentionPriority{PriorityLevel: s00.PriorityLevel(0), PreEmptionCapability: s00.PreEmptionCapability(0), PreEmptionVulnerability: s00.PreEmptionVulnerability(0)}}}))})), handoverRequestIEFieldFreshMust(s60.HandoverRequestIEs().SourceToTargetTransparentContainer().New(make([]byte, 0))), handoverRequestIEFieldFreshMust(s60.HandoverRequestIEs().UESecurityCapabilities().New(s47.UESecurityCapabilities{EncryptionAlgorithms: runtime.BitString{Bytes: make([]byte, 2), BitLength: 16}, IntegrityProtectionAlgorithms: runtime.BitString{Bytes: make([]byte, 2), BitLength: 16}})), handoverRequestIEFieldFreshMust(s60.HandoverRequestIEs().SecurityContext().New(s36.SecurityContext{NextHopChainingCount: int64(0), NextHopParameter: runtime.BitString{Bytes: make([]byte, 32), BitLength: 256}}))}))))))
		}},
		{"HandoverRequestAcknowledge", "200100250000040000400200000008400200000012400d00001440080000000000000000007b000100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s65.HandoverResourceAllocationProcedure().Successful().Build(handoverRequestAcknowledgeFreshMust(s61.NewHandoverRequestAcknowledge(s49.HandoverRequestAcknowledgeIEContainer{handoverRequestAcknowledgeIEFieldFreshMust(s49.HandoverRequestAcknowledgeIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), handoverRequestAcknowledgeIEFieldFreshMust(s49.HandoverRequestAcknowledgeIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), handoverRequestAcknowledgeIEFieldFreshMust(s49.HandoverRequestAcknowledgeIEs().ERABAdmittedList().New(s18.ERABAdmittedList{eRABAdmittedItemIEFieldFreshMust(s18.ERABAdmittedItemIEs().ERABAdmittedItem().New(s18.ERABAdmittedItem{ERABID: big.NewInt(0), TransportLayerAddress: runtime.BitString{Bytes: make([]byte, 1), BitLength: 1}, GTPTEID: make([]byte, 4)}))})), handoverRequestAcknowledgeIEFieldFreshMust(s49.HandoverRequestAcknowledgeIEs().TargetToSourceTransparentContainer().New(make([]byte, 0)))}))))))
		}},
		{"HandoverFailure", "4001000f000002000040020000000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUUnsuccessfulOutcome(unsuccessfulOutcomeFreshMust(s65.HandoverResourceAllocationProcedure().Unsuccessful().Build(handoverFailureFreshMust(s61.NewHandoverFailure(s26.HandoverFailureIEContainer{handoverFailureIEFieldFreshMust(s26.HandoverFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), handoverFailureIEFieldFreshMust(s26.HandoverFailureIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"PathSwitchRequest", "0003003e0000060008000200000016000c00001700070000000000000000580002000000644008000000000000000000434006000000000000006b40050000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.PathSwitchRequestProcedure().Initiating().Build(pathSwitchRequestFreshMust(s63.NewPathSwitchRequest(s51.PathSwitchRequestIEContainer{pathSwitchRequestIEFieldFreshMust(s51.PathSwitchRequestIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), pathSwitchRequestIEFieldFreshMust(s51.PathSwitchRequestIEs().ERABToBeSwitchedDLList().New(s38.ERABToBeSwitchedDLList{eRABToBeSwitchedDLItemIEFieldFreshMust(s38.ERABToBeSwitchedDLItemIEs().ERABToBeSwitchedDLItem().New(s38.ERABToBeSwitchedDLItem{ERABID: big.NewInt(0), TransportLayerAddress: runtime.BitString{Bytes: make([]byte, 1), BitLength: 1}, GTPTEID: make([]byte, 4)}))})), pathSwitchRequestIEFieldFreshMust(s51.PathSwitchRequestIEs().SourceMMEUES1APID().New(s00.MMEUES1APID(0))), pathSwitchRequestIEFieldFreshMust(s51.PathSwitchRequestIEs().EUTRANCGI().New(s20.EUTRANCGI{PLMNidentity: make([]byte, 3), CellID: runtime.BitString{Bytes: make([]byte, 4), BitLength: 28}})), pathSwitchRequestIEFieldFreshMust(s51.PathSwitchRequestIEs().TAI().New(s40.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)})), pathSwitchRequestIEFieldFreshMust(s51.PathSwitchRequestIEs().UESecurityCapabilities().New(s47.UESecurityCapabilities{EncryptionAlgorithms: runtime.BitString{Bytes: make([]byte, 2), BitLength: 16}, IntegrityProtectionAlgorithms: runtime.BitString{Bytes: make([]byte, 2), BitLength: 16}}))}))))))
		}},
		{"PathSwitchRequestAcknowledge", "2003003400000300004002000000084002000000280021000000000000000000000000000000000000000000000000000000000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s66.PathSwitchRequestProcedure().Successful().Build(pathSwitchRequestAcknowledgeFreshMust(s63.NewPathSwitchRequestAcknowledge(s58.PathSwitchRequestAcknowledgeIEContainer{pathSwitchRequestAcknowledgeIEFieldFreshMust(s58.PathSwitchRequestAcknowledgeIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), pathSwitchRequestAcknowledgeIEFieldFreshMust(s58.PathSwitchRequestAcknowledgeIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), pathSwitchRequestAcknowledgeIEFieldFreshMust(s58.PathSwitchRequestAcknowledgeIEs().SecurityContext().New(s36.SecurityContext{NextHopChainingCount: int64(0), NextHopParameter: runtime.BitString{Bytes: make([]byte, 32), BitLength: 256}}))}))))))
		}},
		{"PathSwitchRequestFailure", "40030015000003000040020000000840020000000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUUnsuccessfulOutcome(unsuccessfulOutcomeFreshMust(s66.PathSwitchRequestProcedure().Unsuccessful().Build(pathSwitchRequestFailureFreshMust(s62.NewPathSwitchRequestFailure(s27.PathSwitchRequestFailureIEContainer{pathSwitchRequestFailureIEFieldFreshMust(s27.PathSwitchRequestFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), pathSwitchRequestFailureIEFieldFreshMust(s27.PathSwitchRequestFailureIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), pathSwitchRequestFailureIEFieldFreshMust(s27.PathSwitchRequestFailureIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"E-RABSetupRequest", "0005002400000300000002000000080002000000100011000011000c000000000000000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.ERABSetupProcedure().Initiating().Build(eRABSetupRequestFreshMust(s63.NewERABSetupRequest(s51.ERABSetupRequestIEContainer{eRABSetupRequestIEFieldFreshMust(s51.ERABSetupRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), eRABSetupRequestIEFieldFreshMust(s51.ERABSetupRequestIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), eRABSetupRequestIEFieldFreshMust(s51.ERABSetupRequestIEs().ERABToBeSetupListBearerSUReq().New(s38.ERABToBeSetupListBearerSUReq{eRABToBeSetupItemBearerSUReqIEFieldFreshMust(s38.ERABToBeSetupItemBearerSUReqIEs().ERABToBeSetupItemBearerSUReq().New(s37.ERABToBeSetupItemBearerSUReq{ERABID: big.NewInt(0), ERABlevelQoSParameters: s21.ERABLevelQoSParameters{QCI: s00.QCI(0), AllocationRetentionPriority: s16.AllocationAndRetentionPriority{PriorityLevel: s00.PriorityLevel(0), PreEmptionCapability: s00.PreEmptionCapability(0), PreEmptionVulnerability: s00.PreEmptionVulnerability(0)}}, TransportLayerAddress: runtime.BitString{Bytes: make([]byte, 1), BitLength: 1}, GTPTEID: make([]byte, 4), NASPDU: make([]byte, 0)}))}))}))))))
		}},
		{"E-RABSetupResponse", "2005000f000002000040020000000840020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s65.ERABSetupProcedure().Successful().Build(eRABSetupResponseFreshMust(s63.NewERABSetupResponse(s56.ERABSetupResponseIEContainer{eRABSetupResponseIEFieldFreshMust(s57.ERABSetupResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), eRABSetupResponseIEFieldFreshMust(s57.ERABSetupResponseIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"E-RABModifyRequest", "0006001d000003000000020000000800020000001e000a00002400050000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.ERABModifyProcedure().Initiating().Build(eRABModifyRequestFreshMust(s63.NewERABModifyRequest(s50.ERABModifyRequestIEContainer{eRABModifyRequestIEFieldFreshMust(s51.ERABModifyRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), eRABModifyRequestIEFieldFreshMust(s51.ERABModifyRequestIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), eRABModifyRequestIEFieldFreshMust(s51.ERABModifyRequestIEs().ERABToBeModifiedListBearerModReq().New(s29.ERABToBeModifiedListBearerModReq{eRABToBeModifiedItemBearerModReqIEFieldFreshMust(s29.ERABToBeModifiedItemBearerModReqIEs().ERABToBeModifiedItemBearerModReq().New(s29.ERABToBeModifiedItemBearerModReq{ERABID: big.NewInt(0), ERABLevelQoSParameters: s21.ERABLevelQoSParameters{QCI: s00.QCI(0), AllocationRetentionPriority: s16.AllocationAndRetentionPriority{PriorityLevel: s00.PriorityLevel(0), PreEmptionCapability: s00.PreEmptionCapability(0), PreEmptionVulnerability: s00.PreEmptionVulnerability(0)}}, NASPDU: make([]byte, 0)}))}))}))))))
		}},
		{"E-RABModifyResponse", "2006000f000002000040020000000840020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s65.ERABModifyProcedure().Successful().Build(eRABModifyResponseFreshMust(s63.NewERABModifyResponse(s56.ERABModifyResponseIEContainer{eRABModifyResponseIEFieldFreshMust(s57.ERABModifyResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), eRABModifyResponseIEFieldFreshMust(s57.ERABModifyResponseIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"E-RABReleaseCommand", "0007001b000003000000020000000800020000002140080000234003000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.ERABReleaseProcedure().Initiating().Build(eRABReleaseCommandFreshMust(s63.NewERABReleaseCommand(s49.ERABReleaseCommandIEContainer{eRABReleaseCommandIEFieldFreshMust(s49.ERABReleaseCommandIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), eRABReleaseCommandIEFieldFreshMust(s49.ERABReleaseCommandIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), eRABReleaseCommandIEFieldFreshMust(s49.ERABReleaseCommandIEs().ERABToBeReleasedList().New(s19.ERABList{eRABItemIEFieldFreshMust(s19.ERABItemIEs().ERABItem().New(s19.ERABItem{ERABID: big.NewInt(0), Cause: causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))}))}))}))))))
		}},
		{"E-RABReleaseResponse", "2007000f000002000040020000000840020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s65.ERABReleaseProcedure().Successful().Build(eRABReleaseResponseFreshMust(s63.NewERABReleaseResponse(s56.ERABReleaseResponseIEContainer{eRABReleaseResponseIEFieldFreshMust(s57.ERABReleaseResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), eRABReleaseResponseIEFieldFreshMust(s57.ERABReleaseResponseIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"InitialContextSetupRequest", "00090058000006000000020000000800020000004200040000000000180010000034000b0000000000000000000000006b00050000000000004900200000000000000000000000000000000000000000000000000000000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.InitialContextSetupProcedure().Initiating().Build(initialContextSetupRequestFreshMust(s64.NewInitialContextSetupRequest(s60.InitialContextSetupRequestIEContainer{initialContextSetupRequestIEFieldFreshMust(s60.InitialContextSetupRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), initialContextSetupRequestIEFieldFreshMust(s60.InitialContextSetupRequestIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), initialContextSetupRequestIEFieldFreshMust(s60.InitialContextSetupRequestIEs().UEaggregateMaximumBitrate().New(s45.UEAggregateMaximumBitrate{UEaggregateMaximumBitRateDL: s00.BitRate(0), UEaggregateMaximumBitRateUL: s00.BitRate(0)})), initialContextSetupRequestIEFieldFreshMust(s60.InitialContextSetupRequestIEs().ERABToBeSetupListCtxtSUReq().New(s38.ERABToBeSetupListCtxtSUReq{eRABToBeSetupItemCtxtSUReqIEFieldFreshMust(s38.ERABToBeSetupItemCtxtSUReqIEs().ERABToBeSetupItemCtxtSUReq().New(s38.ERABToBeSetupItemCtxtSUReq{ERABID: big.NewInt(0), ERABlevelQoSParameters: s21.ERABLevelQoSParameters{QCI: s00.QCI(0), AllocationRetentionPriority: s16.AllocationAndRetentionPriority{PriorityLevel: s00.PriorityLevel(0), PreEmptionCapability: s00.PreEmptionCapability(0), PreEmptionVulnerability: s00.PreEmptionVulnerability(0)}}, TransportLayerAddress: runtime.BitString{Bytes: make([]byte, 1), BitLength: 1}, GTPTEID: make([]byte, 4)}))})), initialContextSetupRequestIEFieldFreshMust(s60.InitialContextSetupRequestIEs().UESecurityCapabilities().New(s47.UESecurityCapabilities{EncryptionAlgorithms: runtime.BitString{Bytes: make([]byte, 2), BitLength: 16}, IntegrityProtectionAlgorithms: runtime.BitString{Bytes: make([]byte, 2), BitLength: 16}})), initialContextSetupRequestIEFieldFreshMust(s60.InitialContextSetupRequestIEs().SecurityKey().New(runtime.BitString{Bytes: make([]byte, 32), BitLength: 256}))}))))))
		}},
		{"InitialContextSetupResponse", "2009001f0000030000400200000008400200000033400c000032400700000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s65.InitialContextSetupProcedure().Successful().Build(initialContextSetupResponseFreshMust(s62.NewInitialContextSetupResponse(s50.InitialContextSetupResponseIEContainer{initialContextSetupResponseIEFieldFreshMust(s50.InitialContextSetupResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), initialContextSetupResponseIEFieldFreshMust(s50.InitialContextSetupResponseIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), initialContextSetupResponseIEFieldFreshMust(s50.InitialContextSetupResponseIEs().ERABSetupListCtxtSURes().New(s20.ERABSetupListCtxtSURes{eRABSetupItemCtxtSUResIEFieldFreshMust(s20.ERABSetupItemCtxtSUResIEs().ERABSetupItemCtxtSURes().New(s19.ERABSetupItemCtxtSURes{ERABID: big.NewInt(0), TransportLayerAddress: runtime.BitString{Bytes: make([]byte, 1), BitLength: 1}, GTPTEID: make([]byte, 4)}))}))}))))))
		}},
		{"InitialContextSetupFailure", "40090015000003000040020000000840020000000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUUnsuccessfulOutcome(unsuccessfulOutcomeFreshMust(s65.InitialContextSetupProcedure().Unsuccessful().Build(initialContextSetupFailureFreshMust(s62.NewInitialContextSetupFailure(s26.InitialContextSetupFailureIEContainer{initialContextSetupFailureIEFieldFreshMust(s26.InitialContextSetupFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), initialContextSetupFailureIEFieldFreshMust(s26.InitialContextSetupFailureIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), initialContextSetupFailureIEFieldFreshMust(s26.InitialContextSetupFailureIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"HandoverCancel", "00040015000003000000020000000800020000000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.HandoverCancelProcedure().Initiating().Build(handoverCancelFreshMust(s61.NewHandoverCancel(s21.HandoverCancelIEContainer{handoverCancelIEFieldFreshMust(s21.HandoverCancelIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), handoverCancelIEFieldFreshMust(s21.HandoverCancelIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), handoverCancelIEFieldFreshMust(s21.HandoverCancelIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"HandoverCancelAcknowledge", "2004000f000002000040020000000840020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s65.HandoverCancelProcedure().Successful().Build(handoverCancelAcknowledgeFreshMust(s61.NewHandoverCancelAcknowledge(s26.HandoverCancelAcknowledgeIEContainer{handoverCancelAcknowledgeIEFieldFreshMust(s26.HandoverCancelAcknowledgeIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), handoverCancelAcknowledgeIEFieldFreshMust(s26.HandoverCancelAcknowledgeIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"KillRequest", "002b000f000002006f00020000007000020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.KillProcedure().Initiating().Build(killRequestFreshMust(s64.NewKillRequest(s41.KillRequestIEContainer{killRequestIEFieldFreshMust(s42.KillRequestIEs().MessageIdentifier().New(runtime.BitString{Bytes: make([]byte, 2), BitLength: 16})), killRequestIEFieldFreshMust(s42.KillRequestIEs().SerialNumber().New(runtime.BitString{Bytes: make([]byte, 2), BitLength: 16}))}))))))
		}},
		{"KillResponse", "202b000f000002006f00020000007000020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s65.KillProcedure().Successful().Build(killResponseFreshMust(s63.NewKillResponse(s41.KillResponseIEContainer{killResponseIEFieldFreshMust(s41.KillResponseIEs().MessageIdentifier().New(runtime.BitString{Bytes: make([]byte, 2), BitLength: 16})), killResponseIEFieldFreshMust(s41.KillResponseIEs().SerialNumber().New(runtime.BitString{Bytes: make([]byte, 2), BitLength: 16}))}))))))
		}},
		{"Reset", "000e000e000002000240020000005c000100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.ResetProcedure().Initiating().Build(resetFreshMust(s63.NewReset(s45.ResetIEContainer{resetIEFieldFreshMust(s45.ResetIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0))))), resetIEFieldFreshMust(s45.ResetIEs().ResetType().New(resetTypeFreshMust(s45.NewResetTypeS1Interface(s00.ResetAll(0)))))}))))))
		}},
		{"ResetAcknowledge", "200e0003000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s66.ResetProcedure().Successful().Build(resetAcknowledgeFreshMust(s63.NewResetAcknowledge(s55.ResetAcknowledgeIEContainer{}))))))
		}},
		{"S1SetupRequest", "0011001f000003003b0008000000000000000000400007000000000000000089400100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.S1SetupProcedure().Initiating().Build(s1SetupRequestFreshMust(s62.NewS1SetupRequest(s54.S1SetupRequestIEContainer{s1SetupRequestIEFieldFreshMust(s54.S1SetupRequestIEs().GlobalENBID().New(s21.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: eNBIDFreshMust(s30.NewENBIDMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 20}))})), s1SetupRequestIEFieldFreshMust(s54.S1SetupRequestIEs().SupportedTAs().New(s40.SupportedTAs{s40.SupportedTAsItem{TAC: make([]byte, 2), BroadcastPLMNs: s00.BPLMNs{make([]byte, 3)}}})), s1SetupRequestIEFieldFreshMust(s54.S1SetupRequestIEs().DefaultPagingDRX().New(s00.PagingDRX(0)))}))))))
		}},
		{"S1SetupResponse", "201100170000020069000b00000000000000000000000057400100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s66.S1SetupProcedure().Successful().Build(s1SetupResponseFreshMust(s62.NewS1SetupResponse(s54.S1SetupResponseIEContainer{s1SetupResponseIEFieldFreshMust(s54.S1SetupResponseIEs().ServedGUMMEIs().New(s39.ServedGUMMEIs{s39.ServedGUMMEIsItem{ServedPLMNs: s00.ServedPLMNs{make([]byte, 3)}, ServedGroupIDs: s00.ServedGroupIDs{make([]byte, 2)}, ServedMMECs: s00.ServedMMECs{make([]byte, 1)}}})), s1SetupResponseIEFieldFreshMust(s54.S1SetupResponseIEs().RelativeMMECapacity().New(s00.RelativeMMECapacity(0)))}))))))
		}},
		{"S1SetupFailure", "40110009000001000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUUnsuccessfulOutcome(unsuccessfulOutcomeFreshMust(s66.S1SetupProcedure().Unsuccessful().Build(s1SetupFailureFreshMust(s62.NewS1SetupFailure(s27.S1SetupFailureIEContainer{s1SetupFailureIEFieldFreshMust(s27.S1SetupFailureIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"UEContextModificationRequest", "0015000f000002000000020000000800020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.UEContextModificationProcedure().Initiating().Build(uEContextModificationRequestFreshMust(s64.NewUEContextModificationRequest(s58.UEContextModificationRequestIEContainer{uEContextModificationRequestIEFieldFreshMust(s58.UEContextModificationRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uEContextModificationRequestIEFieldFreshMust(s58.UEContextModificationRequestIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"UEContextModificationResponse", "2015000f000002000040020000000840020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s66.UEContextModificationProcedure().Successful().Build(uEContextModificationResponseFreshMust(s63.NewUEContextModificationResponse(s27.UEContextModificationResponseIEContainer{uEContextModificationResponseIEFieldFreshMust(s27.UEContextModificationResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uEContextModificationResponseIEFieldFreshMust(s27.UEContextModificationResponseIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"UEContextModificationFailure", "40150015000003000040020000000840020000000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUUnsuccessfulOutcome(unsuccessfulOutcomeFreshMust(s66.UEContextModificationProcedure().Unsuccessful().Build(uEContextModificationFailureFreshMust(s63.NewUEContextModificationFailure(s27.UEContextModificationFailureIEContainer{uEContextModificationFailureIEFieldFreshMust(s27.UEContextModificationFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uEContextModificationFailureIEFieldFreshMust(s27.UEContextModificationFailureIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), uEContextModificationFailureIEFieldFreshMust(s27.UEContextModificationFailureIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"UEContextReleaseCommand", "001700110000020063000400000000000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.UEContextReleaseProcedure().Initiating().Build(uEContextReleaseCommandFreshMust(s63.NewUEContextReleaseCommand(s46.UEContextReleaseCommandIEContainer{uEContextReleaseCommandIEFieldFreshMust(s46.UEContextReleaseCommandIEs().UES1APIDs().New(uES1APIDsFreshMust(s46.NewUES1APIDsUES1APIDPair(s46.UES1APIDPair{MMEUES1APID: s00.MMEUES1APID(0), ENBUES1APID: s00.ENBUES1APID(0)})))), uEContextReleaseCommandIEFieldFreshMust(s46.UEContextReleaseCommandIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"UEContextReleaseComplete", "2017000f000002000040020000000840020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s66.UEContextReleaseProcedure().Successful().Build(uEContextReleaseCompleteFreshMust(s63.NewUEContextReleaseComplete(s56.UEContextReleaseCompleteIEContainer{uEContextReleaseCompleteIEFieldFreshMust(s57.UEContextReleaseCompleteIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uEContextReleaseCompleteIEFieldFreshMust(s57.UEContextReleaseCompleteIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"ENBConfigurationUpdate", "001d0003000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.ENBConfigurationUpdateProcedure().Initiating().Build(eNBConfigurationUpdateFreshMust(s62.NewENBConfigurationUpdate(s54.ENBConfigurationUpdateIEContainer{}))))))
		}},
		{"ENBConfigurationUpdateAcknowledge", "201d0003000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s65.ENBConfigurationUpdateProcedure().Successful().Build(eNBConfigurationUpdateAcknowledgeFreshMust(s61.NewENBConfigurationUpdateAcknowledge(s26.ENBConfigurationUpdateAcknowledgeIEContainer{}))))))
		}},
		{"ENBConfigurationUpdateFailure", "401d0009000001000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUUnsuccessfulOutcome(unsuccessfulOutcomeFreshMust(s65.ENBConfigurationUpdateProcedure().Unsuccessful().Build(eNBConfigurationUpdateFailureFreshMust(s61.NewENBConfigurationUpdateFailure(s26.ENBConfigurationUpdateFailureIEContainer{eNBConfigurationUpdateFailureIEFieldFreshMust(s26.ENBConfigurationUpdateFailureIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"MMEConfigurationUpdate", "001e0003000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.MMEConfigurationUpdateProcedure().Initiating().Build(mMEConfigurationUpdateFreshMust(s62.NewMMEConfigurationUpdate(s54.MMEConfigurationUpdateIEContainer{}))))))
		}},
		{"MMEConfigurationUpdateAcknowledge", "201e0003000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s65.MMEConfigurationUpdateProcedure().Successful().Build(mMEConfigurationUpdateAcknowledgeFreshMust(s62.NewMMEConfigurationUpdateAcknowledge(s26.MMEConfigurationUpdateAcknowledgeIEContainer{}))))))
		}},
		{"MMEConfigurationUpdateFailure", "401e0009000001000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUUnsuccessfulOutcome(unsuccessfulOutcomeFreshMust(s65.MMEConfigurationUpdateProcedure().Unsuccessful().Build(mMEConfigurationUpdateFailureFreshMust(s62.NewMMEConfigurationUpdateFailure(s27.MMEConfigurationUpdateFailureIEContainer{mMEConfigurationUpdateFailureIEFieldFreshMust(s27.MMEConfigurationUpdateFailureIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"WriteReplaceWarningRequest", "0024001b000004006f00020000007000020000007200020000007300020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.WriteReplaceWarningProcedure().Initiating().Build(writeReplaceWarningRequestFreshMust(s64.NewWriteReplaceWarningRequest(s42.WriteReplaceWarningRequestIEContainer{writeReplaceWarningRequestIEFieldFreshMust(s42.WriteReplaceWarningRequestIEs().MessageIdentifier().New(runtime.BitString{Bytes: make([]byte, 2), BitLength: 16})), writeReplaceWarningRequestIEFieldFreshMust(s42.WriteReplaceWarningRequestIEs().SerialNumber().New(runtime.BitString{Bytes: make([]byte, 2), BitLength: 16})), writeReplaceWarningRequestIEFieldFreshMust(s42.WriteReplaceWarningRequestIEs().RepetitionPeriod().New(s00.RepetitionPeriod(0))), writeReplaceWarningRequestIEFieldFreshMust(s42.WriteReplaceWarningRequestIEs().NumberofBroadcastRequest().New(s00.NumberofBroadcastRequest(0)))}))))))
		}},
		{"WriteReplaceWarningResponse", "2024000f000002006f00020000007000020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s66.WriteReplaceWarningProcedure().Successful().Build(writeReplaceWarningResponseFreshMust(s64.NewWriteReplaceWarningResponse(s41.WriteReplaceWarningResponseIEContainer{writeReplaceWarningResponseIEFieldFreshMust(s41.WriteReplaceWarningResponseIEs().MessageIdentifier().New(runtime.BitString{Bytes: make([]byte, 2), BitLength: 16})), writeReplaceWarningResponseIEFieldFreshMust(s41.WriteReplaceWarningResponseIEs().SerialNumber().New(runtime.BitString{Bytes: make([]byte, 2), BitLength: 16}))}))))))
		}},
		{"HandoverNotify", "0002402500000400000002000000080002000000644008000000000000000000434006000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.HandoverNotificationProcedure().Initiating().Build(handoverNotifyFreshMust(s63.NewHandoverNotify(s44.HandoverNotifyIEContainer{handoverNotifyIEFieldFreshMust(s44.HandoverNotifyIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), handoverNotifyIEFieldFreshMust(s44.HandoverNotifyIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), handoverNotifyIEFieldFreshMust(s44.HandoverNotifyIEs().EUTRANCGI().New(s20.EUTRANCGI{PLMNidentity: make([]byte, 3), CellID: runtime.BitString{Bytes: make([]byte, 4), BitLength: 28}})), handoverNotifyIEFieldFreshMust(s44.HandoverNotifyIEs().TAI().New(s40.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)}))}))))))
		}},
		{"E-RABReleaseIndication", "0008401b000003000000020000000800020000006e40080000234003000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.ERABReleaseIndicationProcedure().Initiating().Build(eRABReleaseIndicationFreshMust(s63.NewERABReleaseIndication(s56.ERABReleaseIndicationIEContainer{eRABReleaseIndicationIEFieldFreshMust(s57.ERABReleaseIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), eRABReleaseIndicationIEFieldFreshMust(s57.ERABReleaseIndicationIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), eRABReleaseIndicationIEFieldFreshMust(s57.ERABReleaseIndicationIEs().ERABReleasedList().New(s19.ERABList{eRABItemIEFieldFreshMust(s19.ERABItemIEs().ERABItem().New(s19.ERABItem{ERABID: big.NewInt(0), Cause: causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))}))}))}))))))
		}},
		{"Paging", "000a4027000004005040020000002b4006000000000000006d400100002e400b00002f4006000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.PagingProcedure().Initiating().Build(pagingFreshMust(s64.NewPaging(s61.PagingIEContainer{pagingIEFieldFreshMust(s61.PagingIEs().UEIdentityIndexValue().New(runtime.BitString{Bytes: make([]byte, 2), BitLength: 10})), pagingIEFieldFreshMust(s61.PagingIEs().UEPagingID().New(uEPagingIDFreshMust(s36.NewUEPagingIDSTMSI(s36.STMSI{MMEC: make([]byte, 1), MTMSI: make([]byte, 4)})))), pagingIEFieldFreshMust(s61.PagingIEs().CNDomain().New(s00.CNDomain(0))), pagingIEFieldFreshMust(s61.PagingIEs().TAIList().New(s42.TAIList{tAIItemIEFieldFreshMust(s42.TAIItemIEs().TAIItem().New(s42.TAIItem{TAI: s40.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)}}))}))}))))))
		}},
		{"DownlinkNASTransport", "000b4014000003000000020000000800020000001a000100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.DownlinkNASTransportProcedure().Initiating().Build(downlinkNASTransportFreshMust(s62.NewDownlinkNASTransport(s53.DownlinkNASTransportIEContainer{downlinkNASTransportIEFieldFreshMust(s53.DownlinkNASTransportIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), downlinkNASTransportIEFieldFreshMust(s53.DownlinkNASTransportIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), downlinkNASTransportIEFieldFreshMust(s53.DownlinkNASTransportIEs().NASPDU().New(make([]byte, 0)))}))))))
		}},
		{"InitialUEMessage", "000c4029000005000800020000001a000100004300060000000000000064400800000000000000000086400100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.InitialUEMessageProcedure().Initiating().Build(initialUEMessageFreshMust(s63.NewInitialUEMessage(s44.InitialUEMessageIEContainer{initialUEMessageIEFieldFreshMust(s44.InitialUEMessageIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), initialUEMessageIEFieldFreshMust(s44.InitialUEMessageIEs().NASPDU().New(make([]byte, 0))), initialUEMessageIEFieldFreshMust(s44.InitialUEMessageIEs().TAI().New(s40.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)})), initialUEMessageIEFieldFreshMust(s44.InitialUEMessageIEs().EUTRANCGI().New(s20.EUTRANCGI{PLMNidentity: make([]byte, 3), CellID: runtime.BitString{Bytes: make([]byte, 4), BitLength: 28}})), initialUEMessageIEFieldFreshMust(s44.InitialUEMessageIEs().RRCEstablishmentCause().New(s00.RRCEstablishmentCause(0)))}))))))
		}},
		{"UplinkNASTransport", "000d402a000005000000020000000800020000001a00010000644008000000000000000000434006000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.UplinkNASTransportProcedure().Initiating().Build(uplinkNASTransportFreshMust(s63.NewUplinkNASTransport(s41.UplinkNASTransportIEContainer{uplinkNASTransportIEFieldFreshMust(s41.UplinkNASTransportIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uplinkNASTransportIEFieldFreshMust(s41.UplinkNASTransportIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), uplinkNASTransportIEFieldFreshMust(s41.UplinkNASTransportIEs().NASPDU().New(make([]byte, 0))), uplinkNASTransportIEFieldFreshMust(s41.UplinkNASTransportIEs().EUTRANCGI().New(s20.EUTRANCGI{PLMNidentity: make([]byte, 3), CellID: runtime.BitString{Bytes: make([]byte, 4), BitLength: 28}})), uplinkNASTransportIEFieldFreshMust(s41.UplinkNASTransportIEs().TAI().New(s40.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)}))}))))))
		}},
		{"ErrorIndication", "000f4003000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.ErrorIndicationProcedure().Initiating().Build(errorIndicationFreshMust(s62.NewErrorIndication(s36.ErrorIndicationIEContainer{}))))))
		}},
		{"NASNonDeliveryIndication", "0010401a000004000000020000000800020000001a400100000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.NASNonDeliveryIndicationProcedure().Initiating().Build(nASNonDeliveryIndicationFreshMust(s62.NewNASNonDeliveryIndication(s22.NASNonDeliveryIndicationIEContainer{nASNonDeliveryIndicationIEFieldFreshMust(s23.NASNonDeliveryIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), nASNonDeliveryIndicationIEFieldFreshMust(s23.NASNonDeliveryIndicationIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), nASNonDeliveryIndicationIEFieldFreshMust(s23.NASNonDeliveryIndicationIEs().NASPDU().New(make([]byte, 0))), nASNonDeliveryIndicationIEFieldFreshMust(s23.NASNonDeliveryIndicationIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"UEContextReleaseRequest", "00124015000003000000020000000800020000000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.UEContextReleaseRequestProcedure().Initiating().Build(uEContextReleaseRequestFreshMust(s63.NewUEContextReleaseRequest(s53.UEContextReleaseRequestIEContainer{uEContextReleaseRequestIEFieldFreshMust(s53.UEContextReleaseRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uEContextReleaseRequestIEFieldFreshMust(s53.UEContextReleaseRequestIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), uEContextReleaseRequestIEFieldFreshMust(s53.UEContextReleaseRequestIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"DownlinkS1cdma2000tunnelling", "0013401900000400000002000000080002000000470001000046000100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.DownlinkS1cdma2000tunnellingProcedure().Initiating().Build(downlinkS1cdma2000tunnellingFreshMust(s61.NewDownlinkS1cdma2000tunnelling(s50.DownlinkS1cdma2000tunnellingIEContainer{downlinkS1cdma2000tunnellingIEFieldFreshMust(s50.DownlinkS1cdma2000tunnellingIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), downlinkS1cdma2000tunnellingIEFieldFreshMust(s50.DownlinkS1cdma2000tunnellingIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), downlinkS1cdma2000tunnellingIEFieldFreshMust(s50.DownlinkS1cdma2000tunnellingIEs().Cdma2000RATType().New(s00.Cdma2000RATType(0))), downlinkS1cdma2000tunnellingIEFieldFreshMust(s50.DownlinkS1cdma2000tunnellingIEs().Cdma2000PDU().New(make([]byte, 0)))}))))))
		}},
		{"UplinkS1cdma2000tunnelling", "0014401e000005000000020000000800020000004700010000480001000046000100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.UplinkS1cdma2000tunnellingProcedure().Initiating().Build(uplinkS1cdma2000tunnellingFreshMust(s63.NewUplinkS1cdma2000tunnelling(s24.UplinkS1cdma2000tunnellingIEContainer{uplinkS1cdma2000tunnellingIEFieldFreshMust(s25.UplinkS1cdma2000tunnellingIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uplinkS1cdma2000tunnellingIEFieldFreshMust(s25.UplinkS1cdma2000tunnellingIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), uplinkS1cdma2000tunnellingIEFieldFreshMust(s25.UplinkS1cdma2000tunnellingIEs().Cdma2000RATType().New(s00.Cdma2000RATType(0))), uplinkS1cdma2000tunnellingIEFieldFreshMust(s25.UplinkS1cdma2000tunnellingIEs().Cdma2000SectorID().New(make([]byte, 0))), uplinkS1cdma2000tunnellingIEFieldFreshMust(s25.UplinkS1cdma2000tunnellingIEs().Cdma2000PDU().New(make([]byte, 0)))}))))))
		}},
		{"UECapabilityInfoIndication", "00164014000003000000020000000800020000004a400100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.UECapabilityInfoIndicationProcedure().Initiating().Build(uECapabilityInfoIndicationFreshMust(s63.NewUECapabilityInfoIndication(s14.UECapabilityInfoIndicationIEContainer{uECapabilityInfoIndicationIEFieldFreshMust(s14.UECapabilityInfoIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uECapabilityInfoIndicationIEFieldFreshMust(s14.UECapabilityInfoIndicationIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), uECapabilityInfoIndicationIEFieldFreshMust(s14.UECapabilityInfoIndicationIEs().UERadioCapability().New(make([]byte, 0)))}))))))
		}},
		{"ENBStatusTransfer", "00184024000003000000020000000800020000005a001100000059400b0000000000000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.ENBStatusTransferProcedure().Initiating().Build(eNBStatusTransferFreshMust(s61.NewENBStatusTransfer(s25.ENBStatusTransferIEContainer{eNBStatusTransferIEFieldFreshMust(s25.ENBStatusTransferIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), eNBStatusTransferIEFieldFreshMust(s25.ENBStatusTransferIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), eNBStatusTransferIEFieldFreshMust(s25.ENBStatusTransferIEs().ENBStatusTransferTransparentContainer().New(s25.ENBStatusTransferTransparentContainer{BearersSubjectToStatusTransferList: s25.BearersSubjectToStatusTransferList{bearersSubjectToStatusTransferItemIEFieldFreshMust(s25.BearersSubjectToStatusTransferItemIEs().BearersSubjectToStatusTransferItem().New(s25.BearersSubjectToStatusTransferItem{ERABID: big.NewInt(0), ULCOUNTvalue: s16.COUNTvalue{PDCPSN: s00.PDCPSN(0), HFN: s00.HFN(0)}, DLCOUNTvalue: s16.COUNTvalue{PDCPSN: s00.PDCPSN(0), HFN: s00.HFN(0)}}))}}))}))))))
		}},
		{"MMEStatusTransfer", "00194024000003000000020000000800020000005a001100000059400b0000000000000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.MMEStatusTransferProcedure().Initiating().Build(mMEStatusTransferFreshMust(s62.NewMMEStatusTransfer(s25.MMEStatusTransferIEContainer{mMEStatusTransferIEFieldFreshMust(s25.MMEStatusTransferIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), mMEStatusTransferIEFieldFreshMust(s25.MMEStatusTransferIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), mMEStatusTransferIEFieldFreshMust(s25.MMEStatusTransferIEs().ENBStatusTransferTransparentContainer().New(s25.ENBStatusTransferTransparentContainer{BearersSubjectToStatusTransferList: s25.BearersSubjectToStatusTransferList{bearersSubjectToStatusTransferItemIEFieldFreshMust(s25.BearersSubjectToStatusTransferItemIEs().BearersSubjectToStatusTransferItem().New(s25.BearersSubjectToStatusTransferItem{ERABID: big.NewInt(0), ULCOUNTvalue: s16.COUNTvalue{PDCPSN: s00.PDCPSN(0), HFN: s00.HFN(0)}, DLCOUNTvalue: s16.COUNTvalue{PDCPSN: s00.PDCPSN(0), HFN: s00.HFN(0)}}))}}))}))))))
		}},
		{"DeactivateTrace", "001a401b000003000000020000000800020000005640080000000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.DeactivateTraceProcedure().Initiating().Build(deactivateTraceFreshMust(s61.NewDeactivateTrace(s09.DeactivateTraceIEContainer{deactivateTraceIEFieldFreshMust(s09.DeactivateTraceIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), deactivateTraceIEFieldFreshMust(s09.DeactivateTraceIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), deactivateTraceIEFieldFreshMust(s09.DeactivateTraceIEs().EUTRANTraceID().New(make([]byte, 8)))}))))))
		}},
		{"TraceStart", "001b40200000030000000200000008000200000019400d00000000000000000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.TraceStartProcedure().Initiating().Build(traceStartFreshMust(s64.NewTraceStart(s60.TraceStartIEContainer{traceStartIEFieldFreshMust(s60.TraceStartIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), traceStartIEFieldFreshMust(s60.TraceStartIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), traceStartIEFieldFreshMust(s60.TraceStartIEs().TraceActivation().New(s59.TraceActivation{EUTRANTraceID: make([]byte, 8), InterfacesToTrace: runtime.BitString{Bytes: make([]byte, 1), BitLength: 8}, TraceDepth: s00.TraceDepth(0), TraceCollectionEntityIPAddress: runtime.BitString{Bytes: make([]byte, 1), BitLength: 1}}))}))))))
		}},
		{"TraceFailureIndication", "001c4021000004000000020000000800020000005640080000000000000000000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.TraceFailureIndicationProcedure().Initiating().Build(traceFailureIndicationFreshMust(s63.NewTraceFailureIndication(s24.TraceFailureIndicationIEContainer{traceFailureIndicationIEFieldFreshMust(s24.TraceFailureIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), traceFailureIndicationIEFieldFreshMust(s24.TraceFailureIndicationIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), traceFailureIndicationIEFieldFreshMust(s24.TraceFailureIndicationIEs().EUTRANTraceID().New(make([]byte, 8))), traceFailureIndicationIEFieldFreshMust(s24.TraceFailureIndicationIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"CellTrafficTrace", "002a402e00000500000002000000080002000000564008000000000000000000644008000000000000000000834003000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.CellTrafficTraceProcedure().Initiating().Build(cellTrafficTraceFreshMust(s61.NewCellTrafficTrace(s20.CellTrafficTraceIEContainer{cellTrafficTraceIEFieldFreshMust(s21.CellTrafficTraceIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), cellTrafficTraceIEFieldFreshMust(s21.CellTrafficTraceIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), cellTrafficTraceIEFieldFreshMust(s21.CellTrafficTraceIEs().EUTRANTraceID().New(make([]byte, 8))), cellTrafficTraceIEFieldFreshMust(s21.CellTrafficTraceIEs().EUTRANCGI().New(s20.EUTRANCGI{PLMNidentity: make([]byte, 3), CellID: runtime.BitString{Bytes: make([]byte, 4), BitLength: 28}})), cellTrafficTraceIEFieldFreshMust(s21.CellTrafficTraceIEs().TraceCollectionEntityIPAddress().New(runtime.BitString{Bytes: make([]byte, 1), BitLength: 1}))}))))))
		}},
		{"LocationReportingControl", "001f40140000030000000200000008000200000062400100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.LocationReportingControlProcedure().Initiating().Build(locationReportingControlFreshMust(s62.NewLocationReportingControl(s31.LocationReportingControlIEContainer{locationReportingControlIEFieldFreshMust(s31.LocationReportingControlIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), locationReportingControlIEFieldFreshMust(s31.LocationReportingControlIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), locationReportingControlIEFieldFreshMust(s31.LocationReportingControlIEs().RequestType().New(s31.RequestType{EventType: s00.EventType(0), ReportArea: s00.ReportArea(0)}))}))))))
		}},
		{"LocationReportingFailureIndication", "00204015000003000000020000000800020000000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.LocationReportingFailureIndicationProcedure().Initiating().Build(locationReportingFailureIndicationFreshMust(s62.NewLocationReportingFailureIndication(s22.LocationReportingFailureIndicationIEContainer{locationReportingFailureIndicationIEFieldFreshMust(s22.LocationReportingFailureIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), locationReportingFailureIndicationIEFieldFreshMust(s22.LocationReportingFailureIndicationIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), locationReportingFailureIndicationIEFieldFreshMust(s22.LocationReportingFailureIndicationIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"LocationReport", "0021402a000005000000020000000800020000006440080000000000000000004340060000000000000062400100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.LocationReportProcedure().Initiating().Build(locationReportFreshMust(s62.NewLocationReport(s40.LocationReportIEContainer{locationReportIEFieldFreshMust(s41.LocationReportIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), locationReportIEFieldFreshMust(s41.LocationReportIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), locationReportIEFieldFreshMust(s41.LocationReportIEs().EUTRANCGI().New(s20.EUTRANCGI{PLMNidentity: make([]byte, 3), CellID: runtime.BitString{Bytes: make([]byte, 4), BitLength: 28}})), locationReportIEFieldFreshMust(s41.LocationReportIEs().TAI().New(s40.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)})), locationReportIEFieldFreshMust(s41.LocationReportIEs().RequestType().New(s31.RequestType{EventType: s00.EventType(0), ReportArea: s00.ReportArea(0)}))}))))))
		}},
		{"OverloadStart", "002240080000010065000100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.OverloadStartProcedure().Initiating().Build(overloadStartFreshMust(s62.NewOverloadStart(s51.OverloadStartIEContainer{overloadStartIEFieldFreshMust(s52.OverloadStartIEs().OverloadResponse().New(overloadResponseFreshMust(s30.NewOverloadResponseOverloadAction(s00.OverloadAction(0)))))}))))))
		}},
		{"OverloadStop", "00230003000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.OverloadStopProcedure().Initiating().Build(overloadStopFreshMust(s62.NewOverloadStop(s52.OverloadStopIEContainer{}))))))
		}},
		{"ENBDirectInformationTransfer", "00254009000001007900020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.ENBDirectInformationTransferProcedure().Initiating().Build(eNBDirectInformationTransferFreshMust(s63.NewENBDirectInformationTransfer(s43.ENBDirectInformationTransferIEContainer{eNBDirectInformationTransferIEFieldFreshMust(s43.ENBDirectInformationTransferIEs().InterSystemInformationTransferTypeEDT().New(interSystemInformationTransferTypeFreshMust(s43.NewInterSystemInformationTransferTypeRIMTransfer(s43.RIMTransfer{RIMInformation: make([]byte, 0)}))))}))))))
		}},
		{"MMEDirectInformationTransfer", "00264009000001007a00020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.MMEDirectInformationTransferProcedure().Initiating().Build(mMEDirectInformationTransferFreshMust(s63.NewMMEDirectInformationTransfer(s43.MMEDirectInformationTransferIEContainer{mMEDirectInformationTransferIEFieldFreshMust(s43.MMEDirectInformationTransferIEs().InterSystemInformationTransferTypeMDT().New(interSystemInformationTransferTypeFreshMust(s43.NewInterSystemInformationTransferTypeRIMTransfer(s43.RIMTransfer{RIMInformation: make([]byte, 0)}))))}))))))
		}},
		{"ENBConfigurationTransfer", "00284003000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.ENBConfigurationTransferProcedure().Initiating().Build(eNBConfigurationTransferFreshMust(s66.NewENBConfigurationTransfer(s64.ENBConfigurationTransferIEContainer{}))))))
		}},
		{"MMEConfigurationTransfer", "00294003000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.MMEConfigurationTransferProcedure().Initiating().Build(mMEConfigurationTransferFreshMust(s66.NewMMEConfigurationTransfer(s64.MMEConfigurationTransferIEContainer{}))))))
		}},
		{"PrivateMessage", "00274009000000000000400100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.PrivateMessageProcedure().Initiating().Build(privateMessageFreshMust(s58.NewPrivateMessage(s29.PrivateMessageIEsValuePrivateIEContainer{privateMessageIEsValuePrivateIEFieldFreshMust(s29.PrivateMessageIEs().NewOpaque(privateIEIDFreshMust(s30.NewPrivateIEIDLocal(0)), s00.CriticalityIgnore, []byte{0}))}))))))
		}},
		{"UERadioCapabilityMatchRequest", "0030000f000002000000020000000800020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.UERadioCapabilityMatchProcedure().Initiating().Build(uERadioCapabilityMatchRequestFreshMust(s63.NewUERadioCapabilityMatchRequest(s14.UERadioCapabilityMatchRequestIEContainer{uERadioCapabilityMatchRequestIEFieldFreshMust(s14.UERadioCapabilityMatchRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uERadioCapabilityMatchRequestIEFieldFreshMust(s14.UERadioCapabilityMatchRequestIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"UERadioCapabilityMatchResponse", "2030001400000300004002000000084002000000a9000100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s66.UERadioCapabilityMatchProcedure().Successful().Build(uERadioCapabilityMatchResponseFreshMust(s63.NewUERadioCapabilityMatchResponse(s28.UERadioCapabilityMatchResponseIEContainer{uERadioCapabilityMatchResponseIEFieldFreshMust(s28.UERadioCapabilityMatchResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uERadioCapabilityMatchResponseIEFieldFreshMust(s28.UERadioCapabilityMatchResponseIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), uERadioCapabilityMatchResponseIEFieldFreshMust(s28.UERadioCapabilityMatchResponseIEs().VoiceSupportMatchIndicator().New(s00.VoiceSupportMatchIndicator(0)))}))))))
		}},
		{"E-RABModificationIndication", "0032001f00000300000002000000080002000000c7000c0000c8000700000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.ERABModificationIndicationProcedure().Initiating().Build(eRABModificationIndicationFreshMust(s63.NewERABModificationIndication(s56.ERABModificationIndicationIEContainer{eRABModificationIndicationIEFieldFreshMust(s57.ERABModificationIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), eRABModificationIndicationIEFieldFreshMust(s57.ERABModificationIndicationIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), eRABModificationIndicationIEFieldFreshMust(s57.ERABModificationIndicationIEs().ERABToBeModifiedListBearerModInd().New(s20.ERABToBeModifiedListBearerModInd{eRABToBeModifiedItemBearerModIndIEFieldFreshMust(s20.ERABToBeModifiedItemBearerModIndIEs().ERABToBeModifiedItemBearerModInd().New(s20.ERABToBeModifiedItemBearerModInd{ERABID: big.NewInt(0), TransportLayerAddress: runtime.BitString{Bytes: make([]byte, 1), BitLength: 1}, DLGTPTEID: make([]byte, 4)}))}))}))))))
		}},
		{"E-RABModificationConfirm", "2032000f000002000040020000000840020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s65.ERABModificationIndicationProcedure().Successful().Build(eRABModificationConfirmFreshMust(s61.NewERABModificationConfirm(s49.ERABModificationConfirmIEContainer{eRABModificationConfirmIEFieldFreshMust(s49.ERABModificationConfirmIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), eRABModificationConfirmIEFieldFreshMust(s49.ERABModificationConfirmIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"UEContextModificationIndication", "0035000f000002000000020000000800020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.UEContextModificationIndicationProcedure().Initiating().Build(uEContextModificationIndicationFreshMust(s63.NewUEContextModificationIndication(s24.UEContextModificationIndicationIEContainer{uEContextModificationIndicationIEFieldFreshMust(s24.UEContextModificationIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uEContextModificationIndicationIEFieldFreshMust(s24.UEContextModificationIndicationIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"UEContextModificationConfirm", "2035000f000002000040020000000840020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s66.UEContextModificationIndicationProcedure().Successful().Build(uEContextModificationConfirmFreshMust(s63.NewUEContextModificationConfirm(s27.UEContextModificationConfirmIEContainer{uEContextModificationConfirmIEFieldFreshMust(s27.UEContextModificationConfirmIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uEContextModificationConfirmIEFieldFreshMust(s27.UEContextModificationConfirmIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"UEContextSuspendRequest", "0037000f000002000000020000000800020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.UEContextSuspendProcedure().Initiating().Build(uEContextSuspendRequestFreshMust(s63.NewUEContextSuspendRequest(s56.UEContextSuspendRequestIEContainer{uEContextSuspendRequestIEFieldFreshMust(s57.UEContextSuspendRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uEContextSuspendRequestIEFieldFreshMust(s57.UEContextSuspendRequestIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"UEContextSuspendResponse", "2037000f000002000040020000000840020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s66.UEContextSuspendProcedure().Successful().Build(uEContextSuspendResponseFreshMust(s63.NewUEContextSuspendResponse(s36.UEContextSuspendResponseIEContainer{uEContextSuspendResponseIEFieldFreshMust(s37.UEContextSuspendResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uEContextSuspendResponseIEFieldFreshMust(s37.UEContextSuspendResponseIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"UEContextResumeRequest", "0038000f000002000000020000000800020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.UEContextResumeProcedure().Initiating().Build(uEContextResumeRequestFreshMust(s63.NewUEContextResumeRequest(s48.UEContextResumeRequestIEContainer{uEContextResumeRequestIEFieldFreshMust(s48.UEContextResumeRequestIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uEContextResumeRequestIEFieldFreshMust(s48.UEContextResumeRequestIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"UEContextResumeResponse", "2038000f000002000040020000000840020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s66.UEContextResumeProcedure().Successful().Build(uEContextResumeResponseFreshMust(s63.NewUEContextResumeResponse(s48.UEContextResumeResponseIEContainer{uEContextResumeResponseIEFieldFreshMust(s49.UEContextResumeResponseIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uEContextResumeResponseIEFieldFreshMust(s49.UEContextResumeResponseIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"UEContextResumeFailure", "40380015000003000040020000000840020000000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUUnsuccessfulOutcome(unsuccessfulOutcomeFreshMust(s66.UEContextResumeProcedure().Unsuccessful().Build(uEContextResumeFailureFreshMust(s63.NewUEContextResumeFailure(s27.UEContextResumeFailureIEContainer{uEContextResumeFailureIEFieldFreshMust(s28.UEContextResumeFailureIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uEContextResumeFailureIEFieldFreshMust(s28.UEContextResumeFailureIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), uEContextResumeFailureIEFieldFreshMust(s28.UEContextResumeFailureIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"UERadioCapabilityIDMappingRequest", "003f0008000001013a000100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.UERadioCapabilityIDMappingProcedure().Initiating().Build(uERadioCapabilityIDMappingRequestFreshMust(s63.NewUERadioCapabilityIDMappingRequest(s14.UERadioCapabilityIDMappingRequestIEContainer{uERadioCapabilityIDMappingRequestIEFieldFreshMust(s14.UERadioCapabilityIDMappingRequestIEs().UERadioCapabilityID().New(make([]byte, 0)))}))))))
		}},
		{"UERadioCapabilityIDMappingResponse", "203f000d000002013a000100004a400100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s66.UERadioCapabilityIDMappingProcedure().Successful().Build(uERadioCapabilityIDMappingResponseFreshMust(s63.NewUERadioCapabilityIDMappingResponse(s28.UERadioCapabilityIDMappingResponseIEContainer{uERadioCapabilityIDMappingResponseIEFieldFreshMust(s28.UERadioCapabilityIDMappingResponseIEs().UERadioCapabilityID().New(make([]byte, 0))), uERadioCapabilityIDMappingResponseIEFieldFreshMust(s28.UERadioCapabilityIDMappingResponseIEs().UERadioCapability().New(make([]byte, 0)))}))))))
		}},
		{"S1RemovalRequest", "0043000f000001003b00080000000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.S1RemovalProcedure().Initiating().Build(s1RemovalRequestFreshMust(s62.NewS1RemovalRequest(s24.S1RemovalRequestIEContainer{s1RemovalRequestIEFieldFreshMust(s24.S1RemovalRequestIEs().GlobalENBID().New(s21.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: eNBIDFreshMust(s30.NewENBIDMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 20}))}))}))))))
		}},
		{"S1RemovalResponse", "20430003000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUSuccessfulOutcome(successfulOutcomeFreshMust(s66.S1RemovalProcedure().Successful().Build(s1RemovalResponseFreshMust(s62.NewS1RemovalResponse(s27.S1RemovalResponseIEContainer{}))))))
		}},
		{"S1RemovalFailure", "40430009000001000240020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUUnsuccessfulOutcome(unsuccessfulOutcomeFreshMust(s66.S1RemovalProcedure().Unsuccessful().Build(s1RemovalFailureFreshMust(s62.NewS1RemovalFailure(s27.S1RemovalFailureIEContainer{s1RemovalFailureIEFieldFreshMust(s27.S1RemovalFailureIEs().Cause().New(causeFreshMust(s30.NewCauseRadioNetwork(s00.CauseRadioNetwork(0)))))}))))))
		}},
		{"DownlinkUEAssociatedLPPaTransport", "002c401900000400000002000000080002000000940001000093000100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.DownlinkUEAssociatedLPPaTransportProcedure().Initiating().Build(downlinkUEAssociatedLPPaTransportFreshMust(s61.NewDownlinkUEAssociatedLPPaTransport(s09.DownlinkUEAssociatedLPPaTransportIEContainer{downlinkUEAssociatedLPPaTransportIEFieldFreshMust(s09.DownlinkUEAssociatedLPPaTransportIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), downlinkUEAssociatedLPPaTransportIEFieldFreshMust(s09.DownlinkUEAssociatedLPPaTransportIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), downlinkUEAssociatedLPPaTransportIEFieldFreshMust(s09.DownlinkUEAssociatedLPPaTransportIEs().RoutingID().New(s00.RoutingID(0))), downlinkUEAssociatedLPPaTransportIEFieldFreshMust(s09.DownlinkUEAssociatedLPPaTransportIEs().LPPaPDU().New(make([]byte, 0)))}))))))
		}},
		{"UplinkUEAssociatedLPPaTransport", "002d401900000400000002000000080002000000940001000093000100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.UplinkUEAssociatedLPPaTransportProcedure().Initiating().Build(uplinkUEAssociatedLPPaTransportFreshMust(s63.NewUplinkUEAssociatedLPPaTransport(s14.UplinkUEAssociatedLPPaTransportIEContainer{uplinkUEAssociatedLPPaTransportIEFieldFreshMust(s14.UplinkUEAssociatedLPPaTransportIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), uplinkUEAssociatedLPPaTransportIEFieldFreshMust(s14.UplinkUEAssociatedLPPaTransportIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), uplinkUEAssociatedLPPaTransportIEFieldFreshMust(s14.UplinkUEAssociatedLPPaTransportIEs().RoutingID().New(s00.RoutingID(0))), uplinkUEAssociatedLPPaTransportIEFieldFreshMust(s14.UplinkUEAssociatedLPPaTransportIEs().LPPaPDU().New(make([]byte, 0)))}))))))
		}},
		{"DownlinkNonUEAssociatedLPPaTransport", "002e400d00000200940001000093000100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.DownlinkNonUEAssociatedLPPaTransportProcedure().Initiating().Build(downlinkNonUEAssociatedLPPaTransportFreshMust(s61.NewDownlinkNonUEAssociatedLPPaTransport(s09.DownlinkNonUEAssociatedLPPaTransportIEContainer{downlinkNonUEAssociatedLPPaTransportIEFieldFreshMust(s09.DownlinkNonUEAssociatedLPPaTransportIEs().RoutingID().New(s00.RoutingID(0))), downlinkNonUEAssociatedLPPaTransportIEFieldFreshMust(s09.DownlinkNonUEAssociatedLPPaTransportIEs().LPPaPDU().New(make([]byte, 0)))}))))))
		}},
		{"UplinkNonUEAssociatedLPPaTransport", "002f400d00000200940001000093000100", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.UplinkNonUEAssociatedLPPaTransportProcedure().Initiating().Build(uplinkNonUEAssociatedLPPaTransportFreshMust(s63.NewUplinkNonUEAssociatedLPPaTransport(s14.UplinkNonUEAssociatedLPPaTransportIEContainer{uplinkNonUEAssociatedLPPaTransportIEFieldFreshMust(s14.UplinkNonUEAssociatedLPPaTransportIEs().RoutingID().New(s00.RoutingID(0))), uplinkNonUEAssociatedLPPaTransportIEFieldFreshMust(s14.UplinkNonUEAssociatedLPPaTransportIEs().LPPaPDU().New(make([]byte, 0)))}))))))
		}},
		{"PWSRestartIndication", "0031402800000300b60009000000000000000000003b0008000000000000000000bc00080000000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.PWSRestartIndicationProcedure().Initiating().Build(pWSRestartIndicationFreshMust(s63.NewPWSRestartIndication(s55.PWSRestartIndicationIEContainer{pWSRestartIndicationIEFieldFreshMust(s55.PWSRestartIndicationIEs().ECGIListForRestart().New(s20.ECGIListForRestart{s20.EUTRANCGI{PLMNidentity: make([]byte, 3), CellID: runtime.BitString{Bytes: make([]byte, 4), BitLength: 28}}})), pWSRestartIndicationIEFieldFreshMust(s55.PWSRestartIndicationIEs().GlobalENBID().New(s21.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: eNBIDFreshMust(s30.NewENBIDMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 20}))})), pWSRestartIndicationIEFieldFreshMust(s55.PWSRestartIndicationIEs().TAIListForRestart().New(s41.TAIListForRestart{s40.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)}}))}))))))
		}},
		{"RerouteNASRequest", "0034001400000300080002000000e100010000df00020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.RerouteNASRequestProcedure().Initiating().Build(rerouteNASRequestFreshMust(s62.NewRerouteNASRequest(s23.RerouteNASRequestIEContainer{rerouteNASRequestIEFieldFreshMust(s24.RerouteNASRequestIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), rerouteNASRequestIEFieldFreshMust(s24.RerouteNASRequestIEs().S1Message().New(make([]byte, 0))), rerouteNASRequestIEFieldFreshMust(s24.RerouteNASRequestIEs().MMEGroupID().New(make([]byte, 2)))}))))))
		}},
		{"PWSFailureIndication", "0033401c00000200de0009000000000000000000003b00080000000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.PWSFailureIndicationProcedure().Initiating().Build(pWSFailureIndicationFreshMust(s62.NewPWSFailureIndication(s52.PWSFailureIndicationIEContainer{pWSFailureIndicationIEFieldFreshMust(s52.PWSFailureIndicationIEs().PWSfailedECGIList().New(s23.PWSfailedECGIList{s20.EUTRANCGI{PLMNidentity: make([]byte, 3), CellID: runtime.BitString{Bytes: make([]byte, 4), BitLength: 28}}})), pWSFailureIndicationIEFieldFreshMust(s52.PWSFailureIndicationIEs().GlobalENBID().New(s21.GlobalENBID{PLMNidentity: make([]byte, 3), ENBID: eNBIDFreshMust(s30.NewENBIDMacroENBID(runtime.BitString{Bytes: make([]byte, 3), BitLength: 20}))}))}))))))
		}},
		{"ConnectionEstablishmentIndication", "0036000f000002000040020000000840020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.ConnectionEstablishmentIndicationProcedure().Initiating().Build(connectionEstablishmentIndicationFreshMust(s62.NewConnectionEstablishmentIndication(s39.ConnectionEstablishmentIndicationIEContainer{connectionEstablishmentIndicationIEFieldFreshMust(s39.ConnectionEstablishmentIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), connectionEstablishmentIndicationIEFieldFreshMust(s39.ConnectionEstablishmentIndicationIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"NASDeliveryIndication", "0039400f000002000000020000000800020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.NASDeliveryIndicationProcedure().Initiating().Build(nASDeliveryIndicationFreshMust(s62.NewNASDeliveryIndication(s12.NASDeliveryIndicationIEContainer{nASDeliveryIndicationIEFieldFreshMust(s12.NASDeliveryIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), nASDeliveryIndicationIEFieldFreshMust(s12.NASDeliveryIndicationIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"RetrieveUEInformation", "003a000d00000100600006000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.RetrieveUEInformationProcedure().Initiating().Build(retrieveUEInformationFreshMust(s62.NewRetrieveUEInformation(s36.RetrieveUEInformationIEContainer{retrieveUEInformationIEFieldFreshMust(s36.RetrieveUEInformationIEs().STMSI().New(s36.STMSI{MMEC: make([]byte, 1), MTMSI: make([]byte, 4)}))}))))))
		}},
		{"UEInformationTransfer", "003b000d00000100600006000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.UEInformationTransferProcedure().Initiating().Build(uEInformationTransferFreshMust(s63.NewUEInformationTransfer(s39.UEInformationTransferIEContainer{uEInformationTransferIEFieldFreshMust(s40.UEInformationTransferIEs().STMSI().New(s36.STMSI{MMEC: make([]byte, 1), MTMSI: make([]byte, 4)}))}))))))
		}},
		{"ENBCPRelocationIndication", "003c0030000005000800020000006000060000000000000064400800000000000000000043400600000000000000fe0003000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.ENBCPRelocationIndicationProcedure().Initiating().Build(eNBCPRelocationIndicationFreshMust(s63.NewENBCPRelocationIndication(s47.ENBCPRelocationIndicationIEContainer{eNBCPRelocationIndicationIEFieldFreshMust(s47.ENBCPRelocationIndicationIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), eNBCPRelocationIndicationIEFieldFreshMust(s47.ENBCPRelocationIndicationIEs().STMSI().New(s36.STMSI{MMEC: make([]byte, 1), MTMSI: make([]byte, 4)})), eNBCPRelocationIndicationIEFieldFreshMust(s47.ENBCPRelocationIndicationIEs().EUTRANCGI().New(s20.EUTRANCGI{PLMNidentity: make([]byte, 3), CellID: runtime.BitString{Bytes: make([]byte, 4), BitLength: 28}})), eNBCPRelocationIndicationIEFieldFreshMust(s47.ENBCPRelocationIndicationIEs().TAI().New(s40.TAI{PLMNidentity: make([]byte, 3), TAC: make([]byte, 2)})), eNBCPRelocationIndicationIEFieldFreshMust(s47.ENBCPRelocationIndicationIEs().ULCPSecurityInformation().New(s47.ULCPSecurityInformation{UlNASMAC: runtime.BitString{Bytes: make([]byte, 2), BitLength: 16}, UlNASCount: runtime.BitString{Bytes: make([]byte, 1), BitLength: 5}}))}))))))
		}},
		{"MMECPRelocationIndication", "003d000f000002000000020000000800020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.MMECPRelocationIndicationProcedure().Initiating().Build(mMECPRelocationIndicationFreshMust(s62.NewMMECPRelocationIndication(s11.MMECPRelocationIndicationIEContainer{mMECPRelocationIndicationIEFieldFreshMust(s12.MMECPRelocationIndicationIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), mMECPRelocationIndicationIEFieldFreshMust(s12.MMECPRelocationIndicationIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"SecondaryRATDataUsageReport", "003e402b0000030000400200000008400200000108401800010940130000010b400d00000000000000000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s66.SecondaryRATDataUsageReportProcedure().Initiating().Build(secondaryRATDataUsageReportFreshMust(s63.NewSecondaryRATDataUsageReport(s56.SecondaryRATDataUsageReportIEContainer{secondaryRATDataUsageReportIEFieldFreshMust(s57.SecondaryRATDataUsageReportIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), secondaryRATDataUsageReportIEFieldFreshMust(s57.SecondaryRATDataUsageReportIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), secondaryRATDataUsageReportIEFieldFreshMust(s57.SecondaryRATDataUsageReportIEs().SecondaryRATDataUsageReportList().New(s36.SecondaryRATDataUsageReportList{secondaryRATDataUsageReportItemIEFieldFreshMust(s36.SecondaryRATDataUsageReportItemIEs().SecondaryRATDataUsageReportItem().New(s36.SecondaryRATDataUsageReportItem{ERABID: big.NewInt(0), SecondaryRATType: s00.SecondaryRATType(0), ERABUsageReportList: s20.ERABUsageReportList{eRABUsageReportItemIEFieldFreshMust(s20.ERABUsageReportItemIEs().ERABUsageReportItem().New(s20.ERABUsageReportItem{StartTimestamp: make([]byte, 4), EndTimestamp: make([]byte, 4), UsageCountUL: uint64(0), UsageCountDL: uint64(0)}))}}))}))}))))))
		}},
		{"HandoverSuccess", "0040400f000002000000020000000800020000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.HandoverSuccessProcedure().Initiating().Build(handoverSuccessFreshMust(s61.NewHandoverSuccess(s11.HandoverSuccessIEContainer{handoverSuccessIEFieldFreshMust(s11.HandoverSuccessIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), handoverSuccessIEFieldFreshMust(s11.HandoverSuccessIEs().ENBUES1APID().New(s00.ENBUES1APID(0)))}))))))
		}},
		{"ENBEarlyStatusTransfer", "0041001f0000030000000200000008000200000141000c000001424006000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.ENBEarlyStatusTransferProcedure().Initiating().Build(eNBEarlyStatusTransferFreshMust(s61.NewENBEarlyStatusTransfer(s47.ENBEarlyStatusTransferIEContainer{eNBEarlyStatusTransferIEFieldFreshMust(s47.ENBEarlyStatusTransferIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), eNBEarlyStatusTransferIEFieldFreshMust(s47.ENBEarlyStatusTransferIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), eNBEarlyStatusTransferIEFieldFreshMust(s47.ENBEarlyStatusTransferIEs().ENBEarlyStatusTransferTransparentContainer().New(s47.ENBEarlyStatusTransferTransparentContainer{BearersSubjectToEarlyStatusTransferList: s17.BearersSubjectToEarlyStatusTransferList{bearersSubjectToEarlyStatusTransferItemIEFieldFreshMust(s17.BearersSubjectToEarlyStatusTransferItemIEs().BearersSubjectToEarlyStatusTransferItem().New(s17.BearersSubjectToEarlyStatusTransferItem{ERABID: big.NewInt(0), DLCOUNTPDCPSNlength: dLCOUNTPDCPSNlengthFreshMust(s30.NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12(s16.COUNTvalue{PDCPSN: s00.PDCPSN(0), HFN: s00.HFN(0)}))}))}}))}))))))
		}},
		{"MMEEarlyStatusTransfer", "0042401f0000030000000200000008000200000141000c000001424006000000000000", func() s66.S1APPDU {
			return s1APPDUFreshMust(s67.NewS1APPDUInitiatingMessage(initiatingMessageFreshMust(s65.MMEEarlyStatusTransferProcedure().Initiating().Build(mMEEarlyStatusTransferFreshMust(s62.NewMMEEarlyStatusTransfer(s47.MMEEarlyStatusTransferIEContainer{mMEEarlyStatusTransferIEFieldFreshMust(s47.MMEEarlyStatusTransferIEs().MMEUES1APID().New(s00.MMEUES1APID(0))), mMEEarlyStatusTransferIEFieldFreshMust(s47.MMEEarlyStatusTransferIEs().ENBUES1APID().New(s00.ENBUES1APID(0))), mMEEarlyStatusTransferIEFieldFreshMust(s47.MMEEarlyStatusTransferIEs().ENBEarlyStatusTransferTransparentContainer().New(s47.ENBEarlyStatusTransferTransparentContainer{BearersSubjectToEarlyStatusTransferList: s17.BearersSubjectToEarlyStatusTransferList{bearersSubjectToEarlyStatusTransferItemIEFieldFreshMust(s17.BearersSubjectToEarlyStatusTransferItemIEs().BearersSubjectToEarlyStatusTransferItem().New(s17.BearersSubjectToEarlyStatusTransferItem{ERABID: big.NewInt(0), DLCOUNTPDCPSNlength: dLCOUNTPDCPSNlengthFreshMust(s30.NewDLCOUNTPDCPSNlengthDLCOUNTValuePDCPSNlength12(s16.COUNTvalue{PDCPSN: s00.PDCPSN(0), HFN: s00.HFN(0)}))}))}}))}))))))
		}},
	}
	if len(cases) != 101 {
		t.Fatalf("bodies=%d, want 101", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pdu := tc.build()
			report, err := s67.ValidateMessage(&pdu)
			if err != nil || len(report.Issues) != 0 {
				t.Fatalf("validation=%+v err=%v", report, err)
			}
			got, err := pdu.MarshalAPER()
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("wire=%x want=%x", got, want)
			}
			var decoded s66.S1APPDU
			if _, err := decoded.UnmarshalAPER(got); err != nil {
				t.Fatal(err)
			}
			selectedObserve(reflect.ValueOf(&decoded))
			again, err := decoded.MarshalAPER()
			if err != nil || !bytes.Equal(again, want) {
				t.Fatalf("replay=%x err=%v", again, err)
			}
		})
	}
}
