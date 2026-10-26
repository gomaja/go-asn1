// Code generated from the pinned S1AP source closure. DO NOT EDIT.

package s1ap

import (
	bytes "bytes"
	hex "encoding/hex"
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
	s57 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s57"
	s58 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s58"
	s59 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s59"
	s60 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s60"
	s61 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s61"
	s64 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s64"
	s65 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s65"
	s66 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s66"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
	reflect "reflect"
	testing "testing"
)

type censusComplete interface {
	UnmarshalAPER([]byte, ...aper.DecodeOption) (aper.DecodeReport, error)
	MarshalAPER(...aper.EncodeOption) ([]byte, error)
	ReceivedForm() aper.ReceivedForm
}

// Each concrete source type with a fresh marker is checked with a valid
// synthetic complete encoding of its minimal source value.
func TestWithoutReplayEverySourceType(t *testing.T) {
	cases := []struct {
		name, wire string
		value      censusComplete
	}{
		{"ActivatedCellsListComplete", "0000", &s47.ActivatedCellsListComplete{}},
		{"ActivatedCellsListItem", "0000", &s16.ActivatedCellsListItem{}},
		{"AdditionalGUTI", "0000000000000000000000", &s21.AdditionalGUTI{}},
		{"AllocationAndRetentionPriority", "00", &s16.AllocationAndRetentionPriority{}},
		{"AreaScopeOfMDT", "000000000000000000", &s41.AreaScopeOfMDT{}},
		{"AreaScopeOfQMC", "000000000000000000", &s41.AreaScopeOfQMC{}},
		{"AssistanceDataForCECapableUEs", "000000000000000000", &s20.AssistanceDataForCECapableUEs{}},
		{"AssistanceDataForPaging", "00", &s31.AssistanceDataForPaging{}},
		{"AssistanceDataForRecommendedCells", "0000d640080000000000000000", &s31.AssistanceDataForRecommendedCells{}},
		{"BPLMNsComplete", "00000000", &s47.BPLMNsComplete{}},
		{"BearersSubjectToDLDiscardingItem", "000000000000", &s17.BearersSubjectToDLDiscardingItem{}},
		{"BearersSubjectToDLDiscardingListComplete", "00015f4006000000000000", &s47.BearersSubjectToDLDiscardingListComplete{}},
		{"BearersSubjectToEarlyStatusTransferItem", "000000000000", &s17.BearersSubjectToEarlyStatusTransferItem{}},
		{"BearersSubjectToEarlyStatusTransferListComplete", "0001424006000000000000", &s48.BearersSubjectToEarlyStatusTransferListComplete{}},
		{"BearersSubjectToStatusTransferItem", "0000000000000000000000", &s25.BearersSubjectToStatusTransferItem{}},
		{"BearersSubjectToStatusTransferListComplete", "000059400b0000000000000000000000", &s48.BearersSubjectToStatusTransferListComplete{}},
		{"BluetoothMeasConfigNameListComplete", "000000", &s48.BluetoothMeasConfigNameListComplete{}},
		{"BluetoothMeasurementConfiguration", "00", &s16.BluetoothMeasurementConfiguration{}},
		{"BroadcastCancelledAreaList", "00000000000000000000000000", &s41.BroadcastCancelledAreaList{}},
		{"BroadcastCompletedAreaList", "0000000000000000000000", &s41.BroadcastCompletedAreaList{}},
		{"CGI", "0000000000000000", &s16.CGI{}},
		{"CNTypeRestrictionsComplete", "0000000000", &s48.CNTypeRestrictionsComplete{}},
		{"CNTypeRestrictionsItem", "0000000000", &s16.CNTypeRestrictionsItem{}},
		{"COUNTValueExtended", "0000000000", &s16.COUNTValueExtended{}},
		{"COUNTvalue", "0000000000", &s16.COUNTvalue{}},
		{"COUNTvaluePDCPSNlength18", "00000000", &s16.COUNTvaluePDCPSNlength18{}},
		{"CSGIdListComplete", "000000000000", &s48.CSGIdListComplete{}},
		{"CSGIdListItem", "0000000000", &s17.CSGIdListItem{}},
		{"CSGMembershipInfo", "0000000000", &s17.CSGMembershipInfo{}},
		{"CancelledCellinEAIComplete", "000000000000000000000000", &s48.CancelledCellinEAIComplete{}},
		{"CancelledCellinEAIItem", "00000000000000000000", &s20.CancelledCellinEAIItem{}},
		{"CancelledCellinTAIComplete", "000000000000000000000000", &s48.CancelledCellinTAIComplete{}},
		{"CancelledCellinTAIItem", "00000000000000000000", &s20.CancelledCellinTAIItem{}},
		{"CandidateCellListComplete", "0000", &s48.CandidateCellListComplete{}},
		{"CandidatePCI", "00000000", &s17.CandidatePCI{}},
		{"CandidatePCIListComplete", "00000000", &s48.CandidatePCIListComplete{}},
		{"Cause", "0000", &s17.Cause{}},
		{"Cdma2000OneXSRVCCInfo", "00000000", &s17.Cdma2000OneXSRVCCInfo{}},
		{"CellActivationRequest", "00000000", &s26.CellActivationRequest{}},
		{"CellActivationResponse", "000000", &s25.CellActivationResponse{}},
		{"CellBasedMDT", "000000000000000000", &s25.CellBasedMDT{}},
		{"CellBasedQMC", "000000000000000000", &s25.CellBasedQMC{}},
		{"CellIDBroadcastComplete", "00000000000000000000", &s48.CellIDBroadcastComplete{}},
		{"CellIDBroadcastItem", "0000000000000000", &s20.CellIDBroadcastItem{}},
		{"CellIDCancelledComplete", "000000000000000000000000", &s48.CellIDCancelledComplete{}},
		{"CellIDCancelledItem", "00000000000000000000", &s20.CellIDCancelledItem{}},
		{"CellIdListforMDTComplete", "0000000000000000", &s48.CellIdListforMDTComplete{}},
		{"CellIdListforQMCComplete", "0000000000000000", &s48.CellIdListforQMCComplete{}},
		{"CellIdentifierAndCELevelForCECapableUEs", "000000000000000000", &s20.CellIdentifierAndCELevelForCECapableUEs{}},
		{"CellLoadReportingResponse", "0000", &s21.CellLoadReportingResponse{}},
		{"CellStateIndication", "0000000000", &s28.CellStateIndication{}},
		{"CellTrafficTrace", "00000500000002000000080002000000564008000000000000000000644008000000000000000000834003000000", &s25.CellTrafficTrace{}},
		{"CellType", "00", &s17.CellType{}},
		{"CellsToActivateListComplete", "000000", &s48.CellsToActivateListComplete{}},
		{"CellsToActivateListItem", "0000", &s17.CellsToActivateListItem{}},
		{"CompletedCellinEAIComplete", "00000000000000000000", &s48.CompletedCellinEAIComplete{}},
		{"CompletedCellinEAIItem", "0000000000000000", &s20.CompletedCellinEAIItem{}},
		{"CompletedCellinTAIComplete", "00000000000000000000", &s48.CompletedCellinTAIComplete{}},
		{"CompletedCellinTAIItem", "0000000000000000", &s20.CompletedCellinTAIItem{}},
		{"ConnectedengNBItem", "0000000000000000000000", &s40.ConnectedengNBItem{}},
		{"ConnectedengNBListComplete", "000000000000000000000000", &s48.ConnectedengNBListComplete{}},
		{"ConnectionEstablishmentIndication", "000002000040020000000840020000", &s40.ConnectionEstablishmentIndication{}},
		{"ContextatSource", "000000000000000000", &s23.ContextatSource{}},
		{"CriticalityDiagnostics", "00", &s26.CriticalityDiagnostics{}},
		{"CriticalityDiagnosticsIEItem", "00000000", &s17.CriticalityDiagnosticsIEItem{}},
		{"CriticalityDiagnosticsIEListComplete", "0000000000", &s48.CriticalityDiagnosticsIEListComplete{}},
		{"DAPSRequestInfo", "00", &s17.DAPSRequestInfo{}},
		{"DAPSResponseInfo", "00", &s17.DAPSResponseInfo{}},
		{"DAPSResponseInfoItem", "0000", &s17.DAPSResponseInfoItem{}},
		{"DAPSResponseInfoListComplete", "00013f40020000", &s48.DAPSResponseInfoListComplete{}},
		{"DLCOUNTPDCPSNlength", "0000000000", &s17.DLCOUNTPDCPSNlength{}},
		{"DLCPSecurityInformation", "000000", &s17.DLCPSecurityInformation{}},
		{"DLDiscarding", "0000000000", &s17.DLDiscarding{}},
		{"DeactivateTrace", "000003000000020000000800020000005640080000000000000000", &s18.DeactivateTrace{}},
		{"DownlinkNASTransport", "000003000000020000000800020000001a000100", &s53.DownlinkNASTransport{}},
		{"DownlinkNonUEAssociatedLPPaTransport", "00000200940001000093000100", &s18.DownlinkNonUEAssociatedLPPaTransport{}},
		{"DownlinkS1cdma2000tunnelling", "00000400000002000000080002000000470001000046000100", &s50.DownlinkS1cdma2000tunnelling{}},
		{"DownlinkUEAssociatedLPPaTransport", "00000400000002000000080002000000940001000093000100", &s18.DownlinkUEAssociatedLPPaTransport{}},
		{"ECGIListComplete", "00000000000000000000", &s48.ECGIListComplete{}},
		{"ECGIListForRestartComplete", "000000000000000000", &s48.ECGIListForRestartComplete{}},
		{"EHRPDCompositeAvailableCapacity", "0000", &s18.EHRPDCompositeAvailableCapacity{}},
		{"EHRPDMultiSectorLoadReportingResponseItem", "00000000000000000000000000000000000000000000", &s18.EHRPDMultiSectorLoadReportingResponseItem{}},
		{"EHRPDSectorLoadReportingResponse", "0000000000", &s18.EHRPDSectorLoadReportingResponse{}},
		{"ENBCPRelocationIndication", "000005000800020000006000060000000000000064400800000000000000000043400600000000000000fe0003000000", &s47.ENBCPRelocationIndication{}},
		{"ENBConfigurationTransfer", "000000", &s65.ENBConfigurationTransfer{}},
		{"ENBConfigurationUpdate", "000000", &s54.ENBConfigurationUpdate{}},
		{"ENBConfigurationUpdateAcknowledge", "000000", &s28.ENBConfigurationUpdateAcknowledge{}},
		{"ENBConfigurationUpdateFailure", "000001000240020000", &s28.ENBConfigurationUpdateFailure{}},
		{"ENBDirectInformationTransfer", "000001007900020000", &s43.ENBDirectInformationTransfer{}},
		{"ENBEarlyStatusTransfer", "0000030000000200000008000200000141000c000001424006000000000000", &s47.ENBEarlyStatusTransfer{}},
		{"ENBEarlyStatusTransferTransparentContainer", "000001424006000000000000", &s47.ENBEarlyStatusTransferTransparentContainer{}},
		{"ENBID", "00000000", &s18.ENBID{}},
		{"ENBIndirectX2TransportLayerAddressesComplete", "000000", &s48.ENBIndirectX2TransportLayerAddressesComplete{}},
		{"ENBStatusTransfer", "000003000000020000000800020000005a001100000059400b0000000000000000000000", &s28.ENBStatusTransfer{}},
		{"ENBStatusTransferTransparentContainer", "00000059400b0000000000000000000000", &s25.ENBStatusTransferTransparentContainer{}},
		{"ENBX2ExtTLA", "00", &s18.ENBX2ExtTLA{}},
		{"ENBX2ExtTLAsComplete", "00", &s48.ENBX2ExtTLAsComplete{}},
		{"ENBX2GTPTLAsComplete", "000000", &s48.ENBX2GTPTLAsComplete{}},
		{"ENBX2TLAsComplete", "000000", &s48.ENBX2TLAsComplete{}},
		{"ENDCSONConfigurationTransfer", "00000000000000000000000000000000000000000000000000000000", &s64.ENDCSONConfigurationTransfer{}},
		{"ENDCSONTransferType", "000000000000000000000000000000000000000000000000000000", &s40.ENDCSONTransferType{}},
		{"ENDCSONeNBIdentification", "00000000000000000000000000", &s40.ENDCSONeNBIdentification{}},
		{"ENDCSONengNBIdentification", "00000000000000000000000000", &s40.ENDCSONengNBIdentification{}},
		{"ENDCTransferTypeReply", "0000000000000000000000000000000000000000000000000000", &s40.ENDCTransferTypeReply{}},
		{"ENDCTransferTypeRequest", "000000000000000000000000000000000000000000000000000000", &s40.ENDCTransferTypeRequest{}},
		{"EPLMNsComplete", "00000000", &s48.EPLMNsComplete{}},
		{"ERABAdmittedItem", "0000000000000000", &s18.ERABAdmittedItem{}},
		{"ERABAdmittedListComplete", "00001440080000000000000000", &s48.ERABAdmittedListComplete{}},
		{"ERABDataForwardingItem", "0000", &s18.ERABDataForwardingItem{}},
		{"ERABFailedToResumeItemResumeReq", "000000", &s18.ERABFailedToResumeItemResumeReq{}},
		{"ERABFailedToResumeItemResumeRes", "000000", &s18.ERABFailedToResumeItemResumeRes{}},
		{"ERABFailedToResumeListResumeReqComplete", "0000ec0003000000", &s48.ERABFailedToResumeListResumeReqComplete{}},
		{"ERABFailedToResumeListResumeResComplete", "0000ee0003000000", &s48.ERABFailedToResumeListResumeResComplete{}},
		{"ERABFailedToSetupItemHOReqAck", "000000", &s18.ERABFailedToSetupItemHOReqAck{}},
		{"ERABFailedtoSetupListHOReqAckComplete", "0000154003000000", &s49.ERABFailedtoSetupListHOReqAckComplete{}},
		{"ERABInformationListComplete", "00004e400100", &s49.ERABInformationListComplete{}},
		{"ERABInformationListItem", "00", &s37.ERABInformationListItem{}},
		{"ERABItem", "000000", &s19.ERABItem{}},
		{"ERABLevelQoSParameters", "000000", &s21.ERABLevelQoSParameters{}},
		{"ERABListComplete", "0000234003000000", &s49.ERABListComplete{}},
		{"ERABModificationConfirm", "000002000040020000000840020000", &s49.ERABModificationConfirm{}},
		{"ERABModificationIndication", "00000300000002000000080002000000c7000c0000c8000700000000000000", &s57.ERABModificationIndication{}},
		{"ERABModifyItemBearerModConf", "00", &s19.ERABModifyItemBearerModConf{}},
		{"ERABModifyItemBearerModRes", "00", &s19.ERABModifyItemBearerModRes{}},
		{"ERABModifyListBearerModConfComplete", "0000cc400100", &s49.ERABModifyListBearerModConfComplete{}},
		{"ERABModifyListBearerModResComplete", "000025400100", &s49.ERABModifyListBearerModResComplete{}},
		{"ERABModifyRequest", "000003000000020000000800020000001e000a00002400050000000000", &s51.ERABModifyRequest{}},
		{"ERABModifyResponse", "000002000040020000000840020000", &s57.ERABModifyResponse{}},
		{"ERABNotToBeModifiedItemBearerModInd", "00000000000000", &s19.ERABNotToBeModifiedItemBearerModInd{}},
		{"ERABNotToBeModifiedListBearerModIndComplete", "0000ca000700000000000000", &s49.ERABNotToBeModifiedListBearerModIndComplete{}},
		{"ERABReleaseCommand", "000003000000020000000800020000002140080000234003000000", &s49.ERABReleaseCommand{}},
		{"ERABReleaseIndication", "000003000000020000000800020000006e40080000234003000000", &s57.ERABReleaseIndication{}},
		{"ERABReleaseItemBearerRelComp", "00", &s19.ERABReleaseItemBearerRelComp{}},
		{"ERABReleaseListBearerRelCompComplete", "00000f400100", &s49.ERABReleaseListBearerRelCompComplete{}},
		{"ERABReleaseResponse", "000002000040020000000840020000", &s57.ERABReleaseResponse{}},
		{"ERABSecurityResultItem", "0000", &s38.ERABSecurityResultItem{}},
		{"ERABSecurityResultListComplete", "00014e40020000", &s49.ERABSecurityResultListComplete{}},
		{"ERABSetupItemBearerSURes", "00000000000000", &s19.ERABSetupItemBearerSURes{}},
		{"ERABSetupItemCtxtSURes", "00000000000000", &s19.ERABSetupItemCtxtSURes{}},
		{"ERABSetupListBearerSUResComplete", "000027400700000000000000", &s50.ERABSetupListBearerSUResComplete{}},
		{"ERABSetupListCtxtSUResComplete", "000032400700000000000000", &s50.ERABSetupListCtxtSUResComplete{}},
		{"ERABSetupRequest", "00000300000002000000080002000000100011000011000c000000000000000000000000", &s51.ERABSetupRequest{}},
		{"ERABSetupResponse", "000002000040020000000840020000", &s57.ERABSetupResponse{}},
		{"ERABSubjecttoDataForwardingListComplete", "00000e40020000", &s50.ERABSubjecttoDataForwardingListComplete{}},
		{"ERABToBeModifiedItemBearerModInd", "00000000000000", &s20.ERABToBeModifiedItemBearerModInd{}},
		{"ERABToBeModifiedItemBearerModReq", "0000000000", &s29.ERABToBeModifiedItemBearerModReq{}},
		{"ERABToBeModifiedListBearerModIndComplete", "0000c8000700000000000000", &s50.ERABToBeModifiedListBearerModIndComplete{}},
		{"ERABToBeModifiedListBearerModReqComplete", "00002400050000000000", &s50.ERABToBeModifiedListBearerModReqComplete{}},
		{"ERABToBeSetupItemBearerSUReq", "000000000000000000000000", &s37.ERABToBeSetupItemBearerSUReq{}},
		{"ERABToBeSetupItemCtxtSUReq", "0000000000000000000000", &s38.ERABToBeSetupItemCtxtSUReq{}},
		{"ERABToBeSetupItemHOReq", "00000000000000000000", &s38.ERABToBeSetupItemHOReq{}},
		{"ERABToBeSetupListBearerSUReqComplete", "000011000c000000000000000000000000", &s51.ERABToBeSetupListBearerSUReqComplete{}},
		{"ERABToBeSetupListCtxtSUReqComplete", "000034000b0000000000000000000000", &s51.ERABToBeSetupListCtxtSUReqComplete{}},
		{"ERABToBeSetupListHOReqComplete", "00001b000a00000000000000000000", &s51.ERABToBeSetupListHOReqComplete{}},
		{"ERABToBeSwitchedDLItem", "00000000000000", &s38.ERABToBeSwitchedDLItem{}},
		{"ERABToBeSwitchedDLListComplete", "000017000700000000000000", &s51.ERABToBeSwitchedDLListComplete{}},
		{"ERABToBeSwitchedULItem", "00000000000000", &s20.ERABToBeSwitchedULItem{}},
		{"ERABToBeSwitchedULListComplete", "00005e400700000000000000", &s51.ERABToBeSwitchedULListComplete{}},
		{"ERABToBeUpdatedItem", "00", &s37.ERABToBeUpdatedItem{}},
		{"ERABToBeUpdatedListComplete", "000156400100", &s51.ERABToBeUpdatedListComplete{}},
		{"ERABUsageReportItem", "00000000000000000000000000", &s20.ERABUsageReportItem{}},
		{"ERABUsageReportListComplete", "00010b400d00000000000000000000000000", &s51.ERABUsageReportListComplete{}},
		{"EUTRANCGI", "0000000000000000", &s20.EUTRANCGI{}},
		{"EUTRANResponse", "00000000", &s21.EUTRANResponse{}},
		{"EUTRANcellLoadReportingResponse", "0000", &s21.EUTRANcellLoadReportingResponse{}},
		{"EmergencyAreaIDBroadcastComplete", "00000000000000000000000000000000", &s51.EmergencyAreaIDBroadcastComplete{}},
		{"EmergencyAreaIDBroadcastItem", "0000000000000000000000000000", &s26.EmergencyAreaIDBroadcastItem{}},
		{"EmergencyAreaIDCancelledComplete", "000000000000000000000000000000000000", &s51.EmergencyAreaIDCancelledComplete{}},
		{"EmergencyAreaIDCancelledItem", "00000000000000000000000000000000", &s25.EmergencyAreaIDCancelledItem{}},
		{"EmergencyAreaIDListComplete", "0000000000", &s51.EmergencyAreaIDListComplete{}},
		{"EmergencyAreaIDListForRestartComplete", "00000000", &s51.EmergencyAreaIDListForRestartComplete{}},
		{"ErrorIndication", "000000", &s36.ErrorIndication{}},
		{"EventL1LoggedMDTConfig", "000000", &s22.EventL1LoggedMDTConfig{}},
		{"EventTrigger", "00", &s22.EventTrigger{}},
		{"EventTriggeredCellLoadReportingRequest", "00", &s21.EventTriggeredCellLoadReportingRequest{}},
		{"EventTriggeredCellLoadReportingResponse", "0000", &s21.EventTriggeredCellLoadReportingResponse{}},
		{"ExpectedUEActivityBehaviour", "00", &s21.ExpectedUEActivityBehaviour{}},
		{"ExpectedUEBehaviour", "00", &s21.ExpectedUEBehaviour{}},
		{"FailureEventReport", "0000", &s24.FailureEventReport{}},
		{"FiveGSTAI", "00000000000000", &s21.FiveGSTAI{}},
		{"ForbiddenLACsComplete", "00000000", &s51.ForbiddenLACsComplete{}},
		{"ForbiddenLAsComplete", "0000000000000000", &s51.ForbiddenLAsComplete{}},
		{"ForbiddenLAsItem", "0000000000000000", &s21.ForbiddenLAsItem{}},
		{"ForbiddenTACsComplete", "00000000", &s51.ForbiddenTACsComplete{}},
		{"ForbiddenTAsComplete", "0000000000000000", &s51.ForbiddenTAsComplete{}},
		{"ForbiddenTAsItem", "0000000000000000", &s21.ForbiddenTAsItem{}},
		{"GBRQosInformation", "0000000000000000", &s21.GBRQosInformation{}},
		{"GERANCellID", "000000000000000000", &s22.GERANCellID{}},
		{"GNB", "0000000000000000", &s21.GNB{}},
		{"GNBIdentity", "00000000", &s21.GNBIdentity{}},
		{"GUMMEI", "00000000000000", &s21.GUMMEI{}},
		{"GUMMEIListComplete", "0000000000000000", &s51.GUMMEIListComplete{}},
		{"GlobalENBID", "0000000000000000", &s21.GlobalENBID{}},
		{"GlobalEnGNBID", "0000000000000000", &s21.GlobalEnGNBID{}},
		{"GlobalGNBID", "0000000000000000", &s21.GlobalGNBID{}},
		{"GlobalRANNODEID", "0000000000000000", &s23.GlobalRANNODEID{}},
		{"HOReport", "000000000000", &s25.HOReport{}},
		{"HandoverCancel", "000003000000020000000800020000000240020000", &s29.HandoverCancel{}},
		{"HandoverCancelAcknowledge", "000002000040020000000840020000", &s29.HandoverCancelAcknowledge{}},
		{"HandoverCommand", "0000040000000200000008000200000001000100007b000100", &s50.HandoverCommand{}},
		{"HandoverFailure", "000002000040020000000240020000", &s29.HandoverFailure{}},
		{"HandoverNotify", "00000400000002000000080002000000644008000000000000000000434006000000000000", &s44.HandoverNotify{}},
		{"HandoverPreparationFailure", "000003000040020000000840020000000240020000", &s29.HandoverPreparationFailure{}},
		{"HandoverRequest", "000008000000020000000100010000024002000000420004000000000035000f00001b000a000000000000000000000068000100006b0005000000000000280021000000000000000000000000000000000000000000000000000000000000000000", &s60.HandoverRequest{}},
		{"HandoverRequestAcknowledge", "0000040000400200000008400200000012400d00001440080000000000000000007b000100", &s49.HandoverRequestAcknowledge{}},
		{"HandoverRequired", "00000600000002000000080002000000010001000002400200000004000d000000000000000000000000000068000100", &s43.HandoverRequired{}},
		{"HandoverRestrictionList", "00000000", &s53.HandoverRestrictionList{}},
		{"HandoverSuccess", "000002000000020000000800020000", &s21.HandoverSuccess{}},
		{"IEsECGIListComplete", "000000000000000000", &s52.IEsECGIListComplete{}},
		{"IRATCellID", "0000", &s21.IRATCellID{}},
		{"ImmediateMDT", "0000", &s59.ImmediateMDT{}},
		{"InformationOnRecommendedCellsAndENBsForPaging", "0000d6400800000000000000000000d740080000000000000000", &s42.InformationOnRecommendedCellsAndENBsForPaging{}},
		{"InitialContextSetupFailure", "000003000040020000000840020000000240020000", &s30.InitialContextSetupFailure{}},
		{"InitialContextSetupRequest", "000006000000020000000800020000004200040000000000180010000034000b0000000000000000000000006b00050000000000004900200000000000000000000000000000000000000000000000000000000000000000", &s60.InitialContextSetupRequest{}},
		{"InitialContextSetupResponse", "0000030000400200000008400200000033400c000032400700000000000000", &s50.InitialContextSetupResponse{}},
		{"InitialUEMessage", "000005000800020000001a000100004300060000000000000064400800000000000000000086400100", &s45.InitialUEMessage{}},
		{"InitiatingMessage", "00003000000600000002000000080002000000010001000002400200000004000d000000000000000000000000000068000100", &s65.InitiatingMessage{}},
		{"InterSystemInformationTransferType", "0000", &s43.InterSystemInformationTransferType{}},
		{"InterSystemMeasurementItem", "000000000000", &s21.InterSystemMeasurementItem{}},
		{"InterSystemMeasurementListComplete", "00000000000000", &s52.InterSystemMeasurementListComplete{}},
		{"InterSystemMeasurementParameters", "0000", &s28.InterSystemMeasurementParameters{}},
		{"IntersystemMeasurementConfiguration", "0000", &s28.IntersystemMeasurementConfiguration{}},
		{"KillRequest", "000002006f00020000007000020000", &s42.KillRequest{}},
		{"KillResponse", "000002006f00020000007000020000", &s42.KillResponse{}},
		{"LAI", "000000000000", &s22.LAI{}},
		{"LTENTNTAIInformation", "00000000000000", &s22.LTENTNTAIInformation{}},
		{"LastVisitedCellItem", "0000000000000000000000", &s52.LastVisitedCellItem{}},
		{"LastVisitedEUTRANCellInformation", "0000000000000000000000", &s52.LastVisitedEUTRANCellInformation{}},
		{"LastVisitedGERANCellInformation", "00", &s22.LastVisitedGERANCellInformation{}},
		{"LastVisitedPSCellInformation", "000000", &s23.LastVisitedPSCellInformation{}},
		{"LastVisitedPSCellListComplete", "000000", &s52.LastVisitedPSCellListComplete{}},
		{"ListeningSubframePattern", "000000", &s22.ListeningSubframePattern{}},
		{"LocationReport", "000005000000020000000800020000006440080000000000000000004340060000000000000062400100", &s42.LocationReport{}},
		{"LocationReportingControl", "0000030000000200000008000200000062400100", &s31.LocationReportingControl{}},
		{"LocationReportingFailureIndication", "000003000000020000000800020000000240020000", &s30.LocationReportingFailureIndication{}},
		{"LoggedMBSFNMDT", "0000", &s28.LoggedMBSFNMDT{}},
		{"LoggedMDT", "00", &s59.LoggedMDT{}},
		{"LoggedMDTTrigger", "00", &s22.LoggedMDTTrigger{}},
		{"M1PeriodicReporting", "0000", &s22.M1PeriodicReporting{}},
		{"M1ThresholdEventA2", "0000", &s22.M1ThresholdEventA2{}},
		{"M3Configuration", "00", &s22.M3Configuration{}},
		{"M4Configuration", "0000", &s22.M4Configuration{}},
		{"M5Configuration", "0000", &s22.M5Configuration{}},
		{"M6Configuration", "0000", &s22.M6Configuration{}},
		{"M7Configuration", "0000", &s22.M7Configuration{}},
		{"MBSFNResultToLogComplete", "000000", &s52.MBSFNResultToLogComplete{}},
		{"MBSFNResultToLogInfo", "0000", &s22.MBSFNResultToLogInfo{}},
		{"MDTConfiguration", "000000000000000000000000", &s59.MDTConfiguration{}},
		{"MDTMode", "0000", &s59.MDTMode{}},
		{"MDTModeExtension", "00c540020000", &s22.MDTModeExtension{}},
		{"MDTPLMNListComplete", "00000000", &s52.MDTPLMNListComplete{}},
		{"MMECPRelocationIndication", "000002000000020000000800020000", &s22.MMECPRelocationIndication{}},
		{"MMEConfigurationTransfer", "000000", &s65.MMEConfigurationTransfer{}},
		{"MMEConfigurationUpdate", "000000", &s54.MMEConfigurationUpdate{}},
		{"MMEConfigurationUpdateAcknowledge", "000000", &s30.MMEConfigurationUpdateAcknowledge{}},
		{"MMEConfigurationUpdateFailure", "000001000240020000", &s30.MMEConfigurationUpdateFailure{}},
		{"MMEDirectInformationTransfer", "000001007a00020000", &s43.MMEDirectInformationTransfer{}},
		{"MMEEarlyStatusTransfer", "0000030000000200000008000200000141000c000001424006000000000000", &s48.MMEEarlyStatusTransfer{}},
		{"MMEPagingTarget", "0000000000000000", &s40.MMEPagingTarget{}},
		{"MMEStatusTransfer", "000003000000020000000800020000005a001100000059400b0000000000000000000000", &s30.MMEStatusTransfer{}},
		{"MeasurementThresholdA2", "0000", &s22.MeasurementThresholdA2{}},
		{"MeasurementThresholdL1LoggedMDT", "0000", &s22.MeasurementThresholdL1LoggedMDT{}},
		{"MultiCellLoadReportingRequest", "000000", &s28.MultiCellLoadReportingRequest{}},
		{"MultiCellLoadReportingResponseComplete", "0000000000", &s52.MultiCellLoadReportingResponseComplete{}},
		{"MultiCellLoadReportingResponseItem", "00000000", &s22.MultiCellLoadReportingResponseItem{}},
		{"MutingPatternInformation", "00", &s22.MutingPatternInformation{}},
		{"NASDeliveryIndication", "000002000000020000000800020000", &s22.NASDeliveryIndication{}},
		{"NASNonDeliveryIndication", "000004000000020000000800020000001a400100000240020000", &s30.NASNonDeliveryIndication{}},
		{"NBIoTPagingEDRXInformation", "00", &s23.NBIoTPagingEDRXInformation{}},
		{"NGENB", "0000000000000000", &s23.NGENB{}},
		{"NRCGI", "000000000000000000", &s23.NRCGI{}},
		{"NRUESecurityCapabilities", "0000000000", &s23.NRUESecurityCapabilities{}},
		{"NRUESidelinkAggregateMaximumBitrate", "0000", &s23.NRUESidelinkAggregateMaximumBitrate{}},
		{"NRV2XServicesAuthorized", "00", &s23.NRV2XServicesAuthorized{}},
		{"NotificationCellListComplete", "00000000", &s52.NotificationCellListComplete{}},
		{"NotificationCellListItem", "000000", &s23.NotificationCellListItem{}},
		{"OverloadResponse", "00", &s23.OverloadResponse{}},
		{"OverloadStart", "0000010065000100", &s52.OverloadStart{}},
		{"OverloadStop", "000000", &s52.OverloadStop{}},
		{"PC5FlowBitRates", "00000000", &s23.PC5FlowBitRates{}},
		{"PC5QoSFlowItem", "0000", &s23.PC5QoSFlowItem{}},
		{"PC5QoSFlowListComplete", "00000000", &s52.PC5QoSFlowListComplete{}},
		{"PC5QoSParameters", "0000000000", &s28.PC5QoSParameters{}},
		{"PLMNAreaBasedQMC", "00000000", &s23.PLMNAreaBasedQMC{}},
		{"PLMNListforQMCComplete", "00000000", &s52.PLMNListforQMCComplete{}},
		{"PSCellInformation", "000000000000000000", &s23.PSCellInformation{}},
		{"PWSFailureIndication", "00000200de0009000000000000000000003b00080000000000000000", &s52.PWSFailureIndication{}},
		{"PWSRestartIndication", "00000300b60009000000000000000000003b0008000000000000000000bc00080000000000000000", &s55.PWSRestartIndication{}},
		{"PWSfailedECGIListComplete", "000000000000000000", &s52.PWSfailedECGIListComplete{}},
		{"Paging", "000004005040020000002b4006000000000000006d400100002e400b00002f4006000000000000", &s61.Paging{}},
		{"PagingAttemptInformation", "0000", &s23.PagingAttemptInformation{}},
		{"PagingEDRXInformation", "00", &s23.PagingEDRXInformation{}},
		{"PathSwitchRequest", "0000060008000200000016000c00001700070000000000000000580002000000644008000000000000000000434006000000000000006b40050000000000", &s51.PathSwitchRequest{}},
		{"PathSwitchRequestAcknowledge", "00000300004002000000084002000000280021000000000000000000000000000000000000000000000000000000000000000000", &s58.PathSwitchRequestAcknowledge{}},
		{"PathSwitchRequestFailure", "000003000040020000000840020000000240020000", &s30.PathSwitchRequestFailure{}},
		{"PrivateIEID", "000000", &s23.PrivateIEID{}},
		{"PrivateMessage", "000000000000400100", &s30.PrivateMessage{}},
		{"ProSeAuthorized", "00", &s23.ProSeAuthorized{}},
		{"RATRestrictionsComplete", "000000000000", &s53.RATRestrictionsComplete{}},
		{"RATRestrictionsItem", "000000000000", &s23.RATRestrictionsItem{}},
		{"RIMRoutingAddress", "000000000000000000", &s42.RIMRoutingAddress{}},
		{"RIMTransfer", "0000", &s43.RIMTransfer{}},
		{"RLFReportInformation", "0000", &s23.RLFReportInformation{}},
		{"RecommendedCellItem", "0000000000000000", &s30.RecommendedCellItem{}},
		{"RecommendedCellListComplete", "0000d640080000000000000000", &s53.RecommendedCellListComplete{}},
		{"RecommendedCellsForPaging", "0000d640080000000000000000", &s30.RecommendedCellsForPaging{}},
		{"RecommendedENBItem", "0000000000000000", &s40.RecommendedENBItem{}},
		{"RecommendedENBListComplete", "0000d740080000000000000000", &s53.RecommendedENBListComplete{}},
		{"RecommendedENBsForPaging", "0000d740080000000000000000", &s42.RecommendedENBsForPaging{}},
		{"ReportingCellListComplete", "000000", &s53.ReportingCellListComplete{}},
		{"ReportingCellListItem", "0000", &s23.ReportingCellListItem{}},
		{"RequestType", "00", &s31.RequestType{}},
		{"RequestedCellListComplete", "000000", &s53.RequestedCellListComplete{}},
		{"RequestedTNLInfo", "00000000", &s31.RequestedTNLInfo{}},
		{"RerouteNASRequest", "00000300080002000000e100010000df00020000", &s31.RerouteNASRequest{}},
		{"Reset", "000002000240020000005c000100", &s45.Reset{}},
		{"ResetAcknowledge", "000000", &s55.ResetAcknowledge{}},
		{"ResetType", "00", &s45.ResetType{}},
		{"RetrieveUEInformation", "00000100600006000000000000", &s36.RetrieveUEInformation{}},
		{"S1APPDU", "0000003000000600000002000000080002000000010001000002400200000004000d000000000000000000000000000068000100", &s66.S1APPDU{}},
		{"S1RemovalFailure", "000001000240020000", &s31.S1RemovalFailure{}},
		{"S1RemovalRequest", "000001003b00080000000000000000", &s31.S1RemovalRequest{}},
		{"S1RemovalResponse", "000000", &s31.S1RemovalResponse{}},
		{"S1SetupFailure", "000001000240020000", &s31.S1SetupFailure{}},
		{"S1SetupRequest", "000003003b0008000000000000000000400007000000000000000089400100", &s54.S1SetupRequest{}},
		{"S1SetupResponse", "0000020069000b00000000000000000000000057400100", &s54.S1SetupResponse{}},
		{"SONConfigurationTransfer", "000000000000000000000000000000000000000000000000000000", &s64.SONConfigurationTransfer{}},
		{"SONInformation", "00", &s64.SONInformation{}},
		{"SONInformationExtension", "00ce40020000", &s24.SONInformationExtension{}},
		{"SONInformationReply", "00", &s64.SONInformationReply{}},
		{"SONInformationReport", "0000", &s24.SONInformationReport{}},
		{"SONtransferCause", "00", &s24.SONtransferCause{}},
		{"SONtransferRequestContainer", "00", &s28.SONtransferRequestContainer{}},
		{"SONtransferResponseContainer", "0000", &s28.SONtransferResponseContainer{}},
		{"STMSI", "000000000000", &s36.STMSI{}},
		{"ScheduledCommunicationTime", "00", &s36.ScheduledCommunicationTime{}},
		{"SecondaryRATDataUsageReport", "0000030000400200000008400200000108401800010940130000010b400d00000000000000000000000000", &s57.SecondaryRATDataUsageReport{}},
		{"SecondaryRATDataUsageReportItem", "0000010b400d00000000000000000000000000", &s36.SecondaryRATDataUsageReportItem{}},
		{"SecondaryRATDataUsageReportListComplete", "00010940130000010b400d00000000000000000000000000", &s53.SecondaryRATDataUsageReportListComplete{}},
		{"SecurityContext", "000000000000000000000000000000000000000000000000000000000000000000", &s36.SecurityContext{}},
		{"SecurityIndication", "00", &s37.SecurityIndication{}},
		{"SecurityResult", "00", &s38.SecurityResult{}},
		{"SensorMeasConfigNameItem", "00", &s39.SensorMeasConfigNameItem{}},
		{"SensorMeasConfigNameListComplete", "00", &s53.SensorMeasConfigNameListComplete{}},
		{"SensorMeasurementConfiguration", "00", &s39.SensorMeasurementConfiguration{}},
		{"SensorNameConfig", "00", &s39.SensorNameConfig{}},
		{"ServedDCNsComplete", "00", &s53.ServedDCNsComplete{}},
		{"ServedDCNsItem", "00000000", &s39.ServedDCNsItem{}},
		{"ServedGUMMEIsComplete", "0000000000000000000000", &s53.ServedGUMMEIsComplete{}},
		{"ServedGUMMEIsItem", "00000000000000000000", &s39.ServedGUMMEIsItem{}},
		{"ServedGroupIDsComplete", "00000000", &s54.ServedGroupIDsComplete{}},
		{"ServedMMECsComplete", "0000", &s54.ServedMMECsComplete{}},
		{"ServedPLMNsComplete", "00000000", &s54.ServedPLMNsComplete{}},
		{"SourceNgRanNodeID", "0000000000000000000000000000", &s39.SourceNgRanNodeID{}},
		{"SourceNodeID", "000000000000000000000000000000", &s39.SourceNodeID{}},
		{"SourceNodeIDExtension", "fffc400100", &s24.SourceNodeIDExtension{}},
		{"SourceeNBID", "00000000000000000000000000", &s41.SourceeNBID{}},
		{"SourceeNBToTargeteNBTransparentContainer", "000000000000000000000000000000000000000000", &s52.SourceeNBToTargeteNBTransparentContainer{}},
		{"SubscriptionBasedUEDifferentiationInfo", "00", &s39.SubscriptionBasedUEDifferentiationInfo{}},
		{"SuccessfulOutcome", "0000190000040000000200000008000200000001000100007b000100", &s64.SuccessfulOutcome{}},
		{"SupportedTAsComplete", "00000000000000", &s54.SupportedTAsComplete{}},
		{"SupportedTAsItem", "000000000000", &s40.SupportedTAsItem{}},
		{"SynchronisationInformation", "00", &s40.SynchronisationInformation{}},
		{"TABasedMDT", "000000", &s40.TABasedMDT{}},
		{"TABasedQMC", "000000", &s40.TABasedQMC{}},
		{"TACListInLTENTNComplete", "000000", &s54.TACListInLTENTNComplete{}},
		{"TAI", "000000000000", &s40.TAI{}},
		{"TAIBasedMDT", "000000000000", &s41.TAIBasedMDT{}},
		{"TAIBasedQMC", "000000000000", &s41.TAIBasedQMC{}},
		{"TAIBroadcastComplete", "000000000000000000000000000000000000", &s55.TAIBroadcastComplete{}},
		{"TAIBroadcastItem", "00000000000000000000000000000000", &s41.TAIBroadcastItem{}},
		{"TAICancelledComplete", "0000000000000000000000000000000000000000", &s55.TAICancelledComplete{}},
		{"TAICancelledItem", "000000000000000000000000000000000000", &s41.TAICancelledItem{}},
		{"TAIItem", "000000000000", &s42.TAIItem{}},
		{"TAIListComplete", "00002f4006000000000000", &s55.TAIListComplete{}},
		{"TAIListForRestartComplete", "0000000000000000", &s55.TAIListForRestartComplete{}},
		{"TAIListforMDTComplete", "000000000000", &s55.TAIListforMDTComplete{}},
		{"TAIListforQMCComplete", "000000000000", &s55.TAIListforQMCComplete{}},
		{"TAIListforWarningComplete", "0000000000000000", &s55.TAIListforWarningComplete{}},
		{"TAListforMDTComplete", "000000", &s55.TAListforMDTComplete{}},
		{"TAListforQMCComplete", "000000", &s55.TAListforQMCComplete{}},
		{"TargetID", "00000000000000000000000000", &s43.TargetID{}},
		{"TargetNgRanNodeID", "0000000000000000000000000000", &s42.TargetNgRanNodeID{}},
		{"TargetRNCID", "0000000000000000", &s42.TargetRNCID{}},
		{"TargeteNBID", "00000000000000000000000000", &s43.TargeteNBID{}},
		{"TargeteNBToSourceeNBTransparentContainer", "0000", &s50.TargeteNBToSourceeNBTransparentContainer{}},
		{"TimeBasedHandoverInformation", "00000000", &s43.TimeBasedHandoverInformation{}},
		{"TimeSynchronisationInfo", "00", &s44.TimeSynchronisationInfo{}},
		{"TooEarlyInterRATHOReportReportFromEUTRAN", "0000", &s24.TooEarlyInterRATHOReportReportFromEUTRAN{}},
		{"TraceActivation", "00000000000000000000000000", &s59.TraceActivation{}},
		{"TraceFailureIndication", "000004000000020000000800020000005640080000000000000000000240020000", &s44.TraceFailureIndication{}},
		{"TraceStart", "0000030000000200000008000200000019400d00000000000000000000000000", &s61.TraceStart{}},
		{"TransportInformation", "00000000000000", &s24.TransportInformation{}},
		{"TunnelInformation", "000000", &s44.TunnelInformation{}},
		{"UEAggregateMaximumBitrate", "00000000", &s45.UEAggregateMaximumBitrate{}},
		{"UEAppLayerMeasConfig", "00000000000000000000000000", &s45.UEAppLayerMeasConfig{}},
		{"UEAssociatedLogicalS1ConnectionItem", "00", &s45.UEAssociatedLogicalS1ConnectionItem{}},
		{"UEAssociatedLogicalS1ConnectionListResAckComplete", "00005b400100", &s55.UEAssociatedLogicalS1ConnectionListResAckComplete{}},
		{"UEAssociatedLogicalS1ConnectionListResComplete", "00005b000100", &s55.UEAssociatedLogicalS1ConnectionListResComplete{}},
		{"UECapabilityInfoIndication", "000003000000020000000800020000004a400100", &s45.UECapabilityInfoIndication{}},
		{"UEContextModificationConfirm", "000002000040020000000840020000", &s45.UEContextModificationConfirm{}},
		{"UEContextModificationFailure", "000003000040020000000840020000000240020000", &s45.UEContextModificationFailure{}},
		{"UEContextModificationIndication", "000002000000020000000800020000", &s46.UEContextModificationIndication{}},
		{"UEContextModificationRequest", "000002000000020000000800020000", &s58.UEContextModificationRequest{}},
		{"UEContextModificationResponse", "000002000040020000000840020000", &s46.UEContextModificationResponse{}},
		{"UEContextReleaseCommand", "0000020063000400000000000240020000", &s47.UEContextReleaseCommand{}},
		{"UEContextReleaseComplete", "000002000040020000000840020000", &s57.UEContextReleaseComplete{}},
		{"UEContextReleaseRequest", "000003000000020000000800020000000240020000", &s53.UEContextReleaseRequest{}},
		{"UEContextResumeFailure", "000003000040020000000840020000000240020000", &s46.UEContextResumeFailure{}},
		{"UEContextResumeRequest", "000002000000020000000800020000", &s48.UEContextResumeRequest{}},
		{"UEContextResumeResponse", "000002000040020000000840020000", &s49.UEContextResumeResponse{}},
		{"UEContextSuspendRequest", "000002000000020000000800020000", &s57.UEContextSuspendRequest{}},
		{"UEContextSuspendResponse", "000002000040020000000840020000", &s46.UEContextSuspendResponse{}},
		{"UEHistoryInformationComplete", "000000000000000000000000", &s55.UEHistoryInformationComplete{}},
		{"UEInformationTransfer", "00000100600006000000000000", &s46.UEInformationTransfer{}},
		{"UEPagingID", "000000000000", &s36.UEPagingID{}},
		{"UERadioCapabilityIDMappingRequest", "000001013a000100", &s46.UERadioCapabilityIDMappingRequest{}},
		{"UERadioCapabilityIDMappingResponse", "000002013a000100004a400100", &s46.UERadioCapabilityIDMappingResponse{}},
		{"UERadioCapabilityMatchRequest", "000002000000020000000800020000", &s46.UERadioCapabilityMatchRequest{}},
		{"UERadioCapabilityMatchResponse", "00000300004002000000084002000000a9000100", &s46.UERadioCapabilityMatchResponse{}},
		{"UES1APIDPair", "00000000", &s46.UES1APIDPair{}},
		{"UES1APIDs", "00000000", &s46.UES1APIDs{}},
		{"UESecurityCapabilities", "0000000000", &s47.UESecurityCapabilities{}},
		{"UESidelinkAggregateMaximumBitrate", "0000", &s47.UESidelinkAggregateMaximumBitrate{}},
		{"ULCPSecurityInformation", "000000", &s47.ULCPSecurityInformation{}},
		{"UnsuccessfulOutcome", "000015000003000040020000000840020000000240020000", &s46.UnsuccessfulOutcome{}},
		{"UplinkNASTransport", "000005000000020000000800020000001a00010000644008000000000000000000434006000000000000", &s55.UplinkNASTransport{}},
		{"UplinkNonUEAssociatedLPPaTransport", "00000200940001000093000100", &s55.UplinkNonUEAssociatedLPPaTransport{}},
		{"UplinkS1cdma2000tunnelling", "000005000000020000000800020000004700010000480001000046000100", &s55.UplinkS1cdma2000tunnelling{}},
		{"UplinkUEAssociatedLPPaTransport", "00000400000002000000080002000000940001000093000100", &s55.UplinkUEAssociatedLPPaTransport{}},
		{"UserLocationInformation", "00000000000000000000000000", &s55.UserLocationInformation{}},
		{"V2XServicesAuthorized", "00", &s57.V2XServicesAuthorized{}},
		{"WLANMeasConfigNameListComplete", "0000", &s55.WLANMeasConfigNameListComplete{}},
		{"WLANMeasurementConfiguration", "00", &s59.WLANMeasurementConfiguration{}},
		{"WUSAssistanceInformation", "00", &s61.WUSAssistanceInformation{}},
		{"WarningAreaList", "0000000000000000000000", &s41.WarningAreaList{}},
		{"WriteReplaceWarningRequest", "000004006f00020000007000020000007200020000007300020000", &s64.WriteReplaceWarningRequest{}},
		{"WriteReplaceWarningResponse", "000002006f00020000007000020000", &s64.WriteReplaceWarningResponse{}},
		{"X2TNLConfigurationInfo", "000000", &s64.X2TNLConfigurationInfo{}},
	}
	if len(cases) != 439 {
		t.Fatalf("concrete fresh types=%d, want 439", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tc.value.UnmarshalAPER(wire); err != nil {
				t.Fatal(err)
			}
			selectedObserve(reflect.ValueOf(tc.value))
			before := tc.value.ReceivedForm().OriginalBytes()
			copyValue := reflect.ValueOf(tc.value).MethodByName("WithoutReplay").Call(nil)[0]
			copyPointer := reflect.New(copyValue.Type())
			copyPointer.Elem().Set(copyValue)
			copy := copyPointer.Interface().(censusComplete)
			got, err := copy.MarshalAPER()
			if err != nil {
				t.Fatal(err)
			}
			want, err := tc.value.MarshalAPER(aper.WithoutReplay())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("fresh copy %x, option %x", got, want)
			}
			if !bytes.Equal(got, wire) {
				t.Fatalf("preferred encoding %x, independent minimal encoding %x", got, wire)
			}
			if copy.ReceivedForm().Present() {
				t.Fatal("fresh copy retained received form")
			}
			if !bytes.Equal(tc.value.ReceivedForm().OriginalBytes(), before) {
				t.Fatal("copy changed original received form")
			}
			replay, err := tc.value.MarshalAPER()
			if err != nil || !bytes.Equal(replay, wire) {
				t.Fatalf("copy changed original replay: %v", err)
			}
		})
	}
}
