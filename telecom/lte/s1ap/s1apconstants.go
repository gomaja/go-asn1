// Code generated from ASN.1 module "S1AP-Constants". DO NOT EDIT.

package s1ap

import (
	"github.com/gomaja/go-asn1/runtime"
	"github.com/gomaja/go-asn1/runtime/per"
)

// Ensure imports are used.
var (
	_ runtime.BitString
	_ = per.NewBitBuffer
)

const (

	// IdHandoverPreparation is the integer constant for IdHandoverPreparation.
	IdHandoverPreparation int64 = 0

	// IdHandoverResourceAllocation is the integer constant for IdHandoverResourceAllocation.
	IdHandoverResourceAllocation int64 = 1

	// IdHandoverNotification is the integer constant for IdHandoverNotification.
	IdHandoverNotification int64 = 2

	// IdPathSwitchRequest is the integer constant for IdPathSwitchRequest.
	IdPathSwitchRequest int64 = 3

	// IdHandoverCancel is the integer constant for IdHandoverCancel.
	IdHandoverCancel int64 = 4

	// IdERABSetup is the integer constant for IdERABSetup.
	IdERABSetup int64 = 5

	// IdERABModify is the integer constant for IdERABModify.
	IdERABModify int64 = 6

	// IdERABRelease is the integer constant for IdERABRelease.
	IdERABRelease int64 = 7

	// IdERABReleaseIndication is the integer constant for IdERABReleaseIndication.
	IdERABReleaseIndication int64 = 8

	// IdInitialContextSetup is the integer constant for IdInitialContextSetup.
	IdInitialContextSetup int64 = 9

	// IdPaging is the integer constant for IdPaging.
	IdPaging int64 = 10

	// IdDownlinkNASTransport is the integer constant for IdDownlinkNASTransport.
	IdDownlinkNASTransport int64 = 11

	// IdInitialUEMessage is the integer constant for IdInitialUEMessage.
	IdInitialUEMessage int64 = 12

	// IdUplinkNASTransport is the integer constant for IdUplinkNASTransport.
	IdUplinkNASTransport int64 = 13

	// IdReset is the integer constant for IdReset.
	IdReset int64 = 14

	// IdErrorIndication is the integer constant for IdErrorIndication.
	IdErrorIndication int64 = 15

	// IdNASNonDeliveryIndication is the integer constant for IdNASNonDeliveryIndication.
	IdNASNonDeliveryIndication int64 = 16

	// IdS1Setup is the integer constant for IdS1Setup.
	IdS1Setup int64 = 17

	// IdUEContextReleaseRequest is the integer constant for IdUEContextReleaseRequest.
	IdUEContextReleaseRequest int64 = 18

	// IdDownlinkS1cdma2000tunnelling is the integer constant for IdDownlinkS1cdma2000tunnelling.
	IdDownlinkS1cdma2000tunnelling int64 = 19

	// IdUplinkS1cdma2000tunnelling is the integer constant for IdUplinkS1cdma2000tunnelling.
	IdUplinkS1cdma2000tunnelling int64 = 20

	// IdUEContextModification is the integer constant for IdUEContextModification.
	IdUEContextModification int64 = 21

	// IdUECapabilityInfoIndication is the integer constant for IdUECapabilityInfoIndication.
	IdUECapabilityInfoIndication int64 = 22

	// IdUEContextRelease is the integer constant for IdUEContextRelease.
	IdUEContextRelease int64 = 23

	// IdENBStatusTransfer is the integer constant for IdENBStatusTransfer.
	IdENBStatusTransfer int64 = 24

	// IdMMEStatusTransfer is the integer constant for IdMMEStatusTransfer.
	IdMMEStatusTransfer int64 = 25

	// IdDeactivateTrace is the integer constant for IdDeactivateTrace.
	IdDeactivateTrace int64 = 26

	// IdTraceStart is the integer constant for IdTraceStart.
	IdTraceStart int64 = 27

	// IdTraceFailureIndication is the integer constant for IdTraceFailureIndication.
	IdTraceFailureIndication int64 = 28

	// IdENBConfigurationUpdate is the integer constant for IdENBConfigurationUpdate.
	IdENBConfigurationUpdate int64 = 29

	// IdMMEConfigurationUpdate is the integer constant for IdMMEConfigurationUpdate.
	IdMMEConfigurationUpdate int64 = 30

	// IdLocationReportingControl is the integer constant for IdLocationReportingControl.
	IdLocationReportingControl int64 = 31

	// IdLocationReportingFailureIndication is the integer constant for IdLocationReportingFailureIndication.
	IdLocationReportingFailureIndication int64 = 32

	// IdLocationReport is the integer constant for IdLocationReport.
	IdLocationReport int64 = 33

	// IdOverloadStart is the integer constant for IdOverloadStart.
	IdOverloadStart int64 = 34

	// IdOverloadStop is the integer constant for IdOverloadStop.
	IdOverloadStop int64 = 35

	// IdWriteReplaceWarning is the integer constant for IdWriteReplaceWarning.
	IdWriteReplaceWarning int64 = 36

	// IdENBDirectInformationTransfer is the integer constant for IdENBDirectInformationTransfer.
	IdENBDirectInformationTransfer int64 = 37

	// IdMMEDirectInformationTransfer is the integer constant for IdMMEDirectInformationTransfer.
	IdMMEDirectInformationTransfer int64 = 38

	// IdPrivateMessage is the integer constant for IdPrivateMessage.
	IdPrivateMessage int64 = 39

	// IdENBConfigurationTransfer is the integer constant for IdENBConfigurationTransfer.
	IdENBConfigurationTransfer int64 = 40

	// IdMMEConfigurationTransfer is the integer constant for IdMMEConfigurationTransfer.
	IdMMEConfigurationTransfer int64 = 41

	// IdCellTrafficTrace is the integer constant for IdCellTrafficTrace.
	IdCellTrafficTrace int64 = 42

	// IdKill is the integer constant for IdKill.
	IdKill int64 = 43

	// IdDownlinkUEAssociatedLPPaTransport is the integer constant for IdDownlinkUEAssociatedLPPaTransport.
	IdDownlinkUEAssociatedLPPaTransport int64 = 44

	// IdUplinkUEAssociatedLPPaTransport is the integer constant for IdUplinkUEAssociatedLPPaTransport.
	IdUplinkUEAssociatedLPPaTransport int64 = 45

	// IdDownlinkNonUEAssociatedLPPaTransport is the integer constant for IdDownlinkNonUEAssociatedLPPaTransport.
	IdDownlinkNonUEAssociatedLPPaTransport int64 = 46

	// IdUplinkNonUEAssociatedLPPaTransport is the integer constant for IdUplinkNonUEAssociatedLPPaTransport.
	IdUplinkNonUEAssociatedLPPaTransport int64 = 47

	// IdUERadioCapabilityMatch is the integer constant for IdUERadioCapabilityMatch.
	IdUERadioCapabilityMatch int64 = 48

	// IdPWSRestartIndication is the integer constant for IdPWSRestartIndication.
	IdPWSRestartIndication int64 = 49

	// IdERABModificationIndication is the integer constant for IdERABModificationIndication.
	IdERABModificationIndication int64 = 50

	// IdPWSFailureIndication is the integer constant for IdPWSFailureIndication.
	IdPWSFailureIndication int64 = 51

	// IdRerouteNASRequest is the integer constant for IdRerouteNASRequest.
	IdRerouteNASRequest int64 = 52

	// IdUEContextModificationIndication is the integer constant for IdUEContextModificationIndication.
	IdUEContextModificationIndication int64 = 53

	// IdConnectionEstablishmentIndication is the integer constant for IdConnectionEstablishmentIndication.
	IdConnectionEstablishmentIndication int64 = 54

	// IdUEContextSuspend is the integer constant for IdUEContextSuspend.
	IdUEContextSuspend int64 = 55

	// IdUEContextResume is the integer constant for IdUEContextResume.
	IdUEContextResume int64 = 56

	// IdNASDeliveryIndication is the integer constant for IdNASDeliveryIndication.
	IdNASDeliveryIndication int64 = 57

	// IdRetrieveUEInformation is the integer constant for IdRetrieveUEInformation.
	IdRetrieveUEInformation int64 = 58

	// IdUEInformationTransfer is the integer constant for IdUEInformationTransfer.
	IdUEInformationTransfer int64 = 59

	// IdENBCPRelocationIndication is the integer constant for IdENBCPRelocationIndication.
	IdENBCPRelocationIndication int64 = 60

	// IdMMECPRelocationIndication is the integer constant for IdMMECPRelocationIndication.
	IdMMECPRelocationIndication int64 = 61

	// IdSecondaryRATDataUsageReport is the integer constant for IdSecondaryRATDataUsageReport.
	IdSecondaryRATDataUsageReport int64 = 62

	// IdUERadioCapabilityIDMapping is the integer constant for IdUERadioCapabilityIDMapping.
	IdUERadioCapabilityIDMapping int64 = 63

	// IdHandoverSuccess is the integer constant for IdHandoverSuccess.
	IdHandoverSuccess int64 = 64

	// IdENBEarlyStatusTransfer is the integer constant for IdENBEarlyStatusTransfer.
	IdENBEarlyStatusTransfer int64 = 65

	// IdMMEEarlyStatusTransfer is the integer constant for IdMMEEarlyStatusTransfer.
	IdMMEEarlyStatusTransfer int64 = 66

	// IdS1Removal is the integer constant for IdS1Removal.
	IdS1Removal int64 = 67

	// MaxPrivateIEs is the integer constant for MaxPrivateIEs.
	MaxPrivateIEs int64 = 65535

	// MaxProtocolExtensions is the integer constant for MaxProtocolExtensions.
	MaxProtocolExtensions int64 = 65535

	// MaxProtocolIEs is the integer constant for MaxProtocolIEs.
	MaxProtocolIEs int64 = 65535

	// MaxnoofCSGs is the integer constant for MaxnoofCSGs.
	MaxnoofCSGs int64 = 256

	// MaxnoofERABs is the integer constant for MaxnoofERABs.
	MaxnoofERABs int64 = 256

	// MaxnoofTAIs is the integer constant for MaxnoofTAIs.
	MaxnoofTAIs int64 = 256

	// MaxnoofTACs is the integer constant for MaxnoofTACs.
	MaxnoofTACs int64 = 256

	// MaxnoofErrors is the integer constant for MaxnoofErrors.
	MaxnoofErrors int64 = 256

	// MaxnoofBPLMNs is the integer constant for MaxnoofBPLMNs.
	MaxnoofBPLMNs int64 = 6

	// MaxnoofPLMNsPerMME is the integer constant for MaxnoofPLMNsPerMME.
	MaxnoofPLMNsPerMME int64 = 32

	// MaxnoofEPLMNs is the integer constant for MaxnoofEPLMNs.
	MaxnoofEPLMNs int64 = 15

	// MaxnoofEPLMNsPlusOne is the integer constant for MaxnoofEPLMNsPlusOne.
	MaxnoofEPLMNsPlusOne int64 = 16

	// MaxnoofForbLACs is the integer constant for MaxnoofForbLACs.
	MaxnoofForbLACs int64 = 4096

	// MaxnoofForbTACs is the integer constant for MaxnoofForbTACs.
	MaxnoofForbTACs int64 = 4096

	// MaxnoofIndividualS1ConnectionsToReset is the integer constant for MaxnoofIndividualS1ConnectionsToReset.
	MaxnoofIndividualS1ConnectionsToReset int64 = 256

	// MaxnoofCellsinUEHistoryInfo is the integer constant for MaxnoofCellsinUEHistoryInfo.
	MaxnoofCellsinUEHistoryInfo int64 = 16

	// MaxnoofCellsineNB is the integer constant for MaxnoofCellsineNB.
	MaxnoofCellsineNB int64 = 256

	// MaxnoofTAIforWarning is the integer constant for MaxnoofTAIforWarning.
	MaxnoofTAIforWarning int64 = 65535

	// MaxnoofCellID is the integer constant for MaxnoofCellID.
	MaxnoofCellID int64 = 65535

	// MaxnoofDCNs is the integer constant for MaxnoofDCNs.
	MaxnoofDCNs int64 = 32

	// MaxnoofEmergencyAreaID is the integer constant for MaxnoofEmergencyAreaID.
	MaxnoofEmergencyAreaID int64 = 65535

	// MaxnoofCellinTAI is the integer constant for MaxnoofCellinTAI.
	MaxnoofCellinTAI int64 = 65535

	// MaxnoofCellinEAI is the integer constant for MaxnoofCellinEAI.
	MaxnoofCellinEAI int64 = 65535

	// MaxnoofeNBX2TLAs is the integer constant for MaxnoofeNBX2TLAs.
	MaxnoofeNBX2TLAs int64 = 2

	// MaxnoofeNBX2ExtTLAs is the integer constant for MaxnoofeNBX2ExtTLAs.
	MaxnoofeNBX2ExtTLAs int64 = 16

	// MaxnoofeNBX2GTPTLAs is the integer constant for MaxnoofeNBX2GTPTLAs.
	MaxnoofeNBX2GTPTLAs int64 = 16

	// MaxnoofRATs is the integer constant for MaxnoofRATs.
	MaxnoofRATs int64 = 8

	// MaxnoofGroupIDs is the integer constant for MaxnoofGroupIDs.
	MaxnoofGroupIDs int64 = 65535

	// MaxnoofMMECs is the integer constant for MaxnoofMMECs.
	MaxnoofMMECs int64 = 256

	// MaxnoofCellIDforMDT is the integer constant for MaxnoofCellIDforMDT.
	MaxnoofCellIDforMDT int64 = 32

	// MaxnoofTAforMDT is the integer constant for MaxnoofTAforMDT.
	MaxnoofTAforMDT int64 = 8

	// MaxnoofMDTPLMNs is the integer constant for MaxnoofMDTPLMNs.
	MaxnoofMDTPLMNs int64 = 16

	// MaxnoofCellsforRestart is the integer constant for MaxnoofCellsforRestart.
	MaxnoofCellsforRestart int64 = 256

	// MaxnoofRestartTAIs is the integer constant for MaxnoofRestartTAIs.
	MaxnoofRestartTAIs int64 = 2048

	// MaxnoofRestartEmergencyAreaIDs is the integer constant for MaxnoofRestartEmergencyAreaIDs.
	MaxnoofRestartEmergencyAreaIDs int64 = 256

	// MaxEARFCN is the integer constant for MaxEARFCN.
	MaxEARFCN int64 = 262143

	// MaxnoofMBSFNAreaMDT is the integer constant for MaxnoofMBSFNAreaMDT.
	MaxnoofMBSFNAreaMDT int64 = 8

	// MaxnoofRecommendedCells is the integer constant for MaxnoofRecommendedCells.
	MaxnoofRecommendedCells int64 = 16

	// MaxnoofRecommendedENBs is the integer constant for MaxnoofRecommendedENBs.
	MaxnoofRecommendedENBs int64 = 16

	// Maxnooftimeperiods is the integer constant for Maxnooftimeperiods.
	Maxnooftimeperiods int64 = 2

	// MaxnoofCellIDforQMC is the integer constant for MaxnoofCellIDforQMC.
	MaxnoofCellIDforQMC int64 = 32

	// MaxnoofTAforQMC is the integer constant for MaxnoofTAforQMC.
	MaxnoofTAforQMC int64 = 8

	// MaxnoofPLMNforQMC is the integer constant for MaxnoofPLMNforQMC.
	MaxnoofPLMNforQMC int64 = 16

	// MaxnoofBluetoothName is the integer constant for MaxnoofBluetoothName.
	MaxnoofBluetoothName int64 = 4

	// MaxnoofWLANName is the integer constant for MaxnoofWLANName.
	MaxnoofWLANName int64 = 4

	// MaxnoofConnectedengNBs is the integer constant for MaxnoofConnectedengNBs.
	MaxnoofConnectedengNBs int64 = 256

	// MaxnoofPC5QoSFlows is the integer constant for MaxnoofPC5QoSFlows.
	MaxnoofPC5QoSFlows int64 = 2048

	// Maxnooffrequencies is the integer constant for Maxnooffrequencies.
	Maxnooffrequencies int64 = 64

	// MaxNARFCN is the integer constant for MaxNARFCN.
	MaxNARFCN int64 = 3.279165e+06

	// MaxRSIndexCellQual is the integer constant for MaxRSIndexCellQual.
	MaxRSIndexCellQual int64 = 16

	// MaxnoofPSCellsPerPrimaryCellinUEHistoryInfo is the integer constant for MaxnoofPSCellsPerPrimaryCellinUEHistoryInfo.
	MaxnoofPSCellsPerPrimaryCellinUEHistoryInfo int64 = 8

	// MaxnoofTACsInNTN is the integer constant for MaxnoofTACsInNTN.
	MaxnoofTACsInNTN int64 = 12

	// MaxnoofSensorName is the integer constant for MaxnoofSensorName.
	MaxnoofSensorName int64 = 3

	// IdMMEUES1APID is the integer constant for IdMMEUES1APID.
	IdMMEUES1APID int64 = 0

	// IdHandoverType is the integer constant for IdHandoverType.
	IdHandoverType int64 = 1

	// IdCause is the integer constant for IdCause.
	IdCause int64 = 2

	// IdSourceID is the integer constant for IdSourceID.
	IdSourceID int64 = 3

	// IdTargetID is the integer constant for IdTargetID.
	IdTargetID int64 = 4

	// IdUnknown5 is the integer constant for IdUnknown5.
	IdUnknown5 int64 = 5

	// IdUnknown6 is the integer constant for IdUnknown6.
	IdUnknown6 int64 = 6

	// IdUnknown7 is the integer constant for IdUnknown7.
	IdUnknown7 int64 = 7

	// IdENBUES1APID is the integer constant for IdENBUES1APID.
	IdENBUES1APID int64 = 8

	// IdUnknown9 is the integer constant for IdUnknown9.
	IdUnknown9 int64 = 9

	// IdUnknown10 is the integer constant for IdUnknown10.
	IdUnknown10 int64 = 10

	// IdUnknown11 is the integer constant for IdUnknown11.
	IdUnknown11 int64 = 11

	// IdERABSubjecttoDataForwardingList is the integer constant for IdERABSubjecttoDataForwardingList.
	IdERABSubjecttoDataForwardingList int64 = 12

	// IdERABtoReleaseListHOCmd is the integer constant for IdERABtoReleaseListHOCmd.
	IdERABtoReleaseListHOCmd int64 = 13

	// IdERABDataForwardingItem is the integer constant for IdERABDataForwardingItem.
	IdERABDataForwardingItem int64 = 14

	// IdERABReleaseItemBearerRelComp is the integer constant for IdERABReleaseItemBearerRelComp.
	IdERABReleaseItemBearerRelComp int64 = 15

	// IdERABToBeSetupListBearerSUReq is the integer constant for IdERABToBeSetupListBearerSUReq.
	IdERABToBeSetupListBearerSUReq int64 = 16

	// IdERABToBeSetupItemBearerSUReq is the integer constant for IdERABToBeSetupItemBearerSUReq.
	IdERABToBeSetupItemBearerSUReq int64 = 17

	// IdERABAdmittedList is the integer constant for IdERABAdmittedList.
	IdERABAdmittedList int64 = 18

	// IdERABFailedToSetupListHOReqAck is the integer constant for IdERABFailedToSetupListHOReqAck.
	IdERABFailedToSetupListHOReqAck int64 = 19

	// IdERABAdmittedItem is the integer constant for IdERABAdmittedItem.
	IdERABAdmittedItem int64 = 20

	// IdERABFailedtoSetupItemHOReqAck is the integer constant for IdERABFailedtoSetupItemHOReqAck.
	IdERABFailedtoSetupItemHOReqAck int64 = 21

	// IdERABToBeSwitchedDLList is the integer constant for IdERABToBeSwitchedDLList.
	IdERABToBeSwitchedDLList int64 = 22

	// IdERABToBeSwitchedDLItem is the integer constant for IdERABToBeSwitchedDLItem.
	IdERABToBeSwitchedDLItem int64 = 23

	// IdERABToBeSetupListCtxtSUReq is the integer constant for IdERABToBeSetupListCtxtSUReq.
	IdERABToBeSetupListCtxtSUReq int64 = 24

	// IdTraceActivation is the integer constant for IdTraceActivation.
	IdTraceActivation int64 = 25

	// IdNASPDU is the integer constant for IdNASPDU.
	IdNASPDU int64 = 26

	// IdERABToBeSetupItemHOReq is the integer constant for IdERABToBeSetupItemHOReq.
	IdERABToBeSetupItemHOReq int64 = 27

	// IdERABSetupListBearerSURes is the integer constant for IdERABSetupListBearerSURes.
	IdERABSetupListBearerSURes int64 = 28

	// IdERABFailedToSetupListBearerSURes is the integer constant for IdERABFailedToSetupListBearerSURes.
	IdERABFailedToSetupListBearerSURes int64 = 29

	// IdERABToBeModifiedListBearerModReq is the integer constant for IdERABToBeModifiedListBearerModReq.
	IdERABToBeModifiedListBearerModReq int64 = 30

	// IdERABModifyListBearerModRes is the integer constant for IdERABModifyListBearerModRes.
	IdERABModifyListBearerModRes int64 = 31

	// IdERABFailedToModifyList is the integer constant for IdERABFailedToModifyList.
	IdERABFailedToModifyList int64 = 32

	// IdERABToBeReleasedList is the integer constant for IdERABToBeReleasedList.
	IdERABToBeReleasedList int64 = 33

	// IdERABFailedToReleaseList is the integer constant for IdERABFailedToReleaseList.
	IdERABFailedToReleaseList int64 = 34

	// IdERABItem is the integer constant for IdERABItem.
	IdERABItem int64 = 35

	// IdERABToBeModifiedItemBearerModReq is the integer constant for IdERABToBeModifiedItemBearerModReq.
	IdERABToBeModifiedItemBearerModReq int64 = 36

	// IdERABModifyItemBearerModRes is the integer constant for IdERABModifyItemBearerModRes.
	IdERABModifyItemBearerModRes int64 = 37

	// IdERABReleaseItem is the integer constant for IdERABReleaseItem.
	IdERABReleaseItem int64 = 38

	// IdERABSetupItemBearerSURes is the integer constant for IdERABSetupItemBearerSURes.
	IdERABSetupItemBearerSURes int64 = 39

	// IdSecurityContext is the integer constant for IdSecurityContext.
	IdSecurityContext int64 = 40

	// IdHandoverRestrictionList is the integer constant for IdHandoverRestrictionList.
	IdHandoverRestrictionList int64 = 41

	// IdUnknown42 is the integer constant for IdUnknown42.
	IdUnknown42 int64 = 42

	// IdUEPagingID is the integer constant for IdUEPagingID.
	IdUEPagingID int64 = 43

	// IdPagingDRX is the integer constant for IdPagingDRX.
	IdPagingDRX int64 = 44

	// IdUnknown45 is the integer constant for IdUnknown45.
	IdUnknown45 int64 = 45

	// IdTAIList is the integer constant for IdTAIList.
	IdTAIList int64 = 46

	// IdTAIItem is the integer constant for IdTAIItem.
	IdTAIItem int64 = 47

	// IdERABFailedToSetupListCtxtSURes is the integer constant for IdERABFailedToSetupListCtxtSURes.
	IdERABFailedToSetupListCtxtSURes int64 = 48

	// IdERABReleaseItemHOCmd is the integer constant for IdERABReleaseItemHOCmd.
	IdERABReleaseItemHOCmd int64 = 49

	// IdERABSetupItemCtxtSURes is the integer constant for IdERABSetupItemCtxtSURes.
	IdERABSetupItemCtxtSURes int64 = 50

	// IdERABSetupListCtxtSURes is the integer constant for IdERABSetupListCtxtSURes.
	IdERABSetupListCtxtSURes int64 = 51

	// IdERABToBeSetupItemCtxtSUReq is the integer constant for IdERABToBeSetupItemCtxtSUReq.
	IdERABToBeSetupItemCtxtSUReq int64 = 52

	// IdERABToBeSetupListHOReq is the integer constant for IdERABToBeSetupListHOReq.
	IdERABToBeSetupListHOReq int64 = 53

	// IdUnknown54 is the integer constant for IdUnknown54.
	IdUnknown54 int64 = 54

	// IdGERANtoLTEHOInformationRes is the integer constant for IdGERANtoLTEHOInformationRes.
	IdGERANtoLTEHOInformationRes int64 = 55

	// IdUnknown56 is the integer constant for IdUnknown56.
	IdUnknown56 int64 = 56

	// IdUTRANtoLTEHOInformationRes is the integer constant for IdUTRANtoLTEHOInformationRes.
	IdUTRANtoLTEHOInformationRes int64 = 57

	// IdCriticalityDiagnostics is the integer constant for IdCriticalityDiagnostics.
	IdCriticalityDiagnostics int64 = 58

	// IdGlobalENBID is the integer constant for IdGlobalENBID.
	IdGlobalENBID int64 = 59

	// IdENBname is the integer constant for IdENBname.
	IdENBname int64 = 60

	// IdMMEname is the integer constant for IdMMEname.
	IdMMEname int64 = 61

	// IdUnknown62 is the integer constant for IdUnknown62.
	IdUnknown62 int64 = 62

	// IdServedPLMNs is the integer constant for IdServedPLMNs.
	IdServedPLMNs int64 = 63

	// IdSupportedTAs is the integer constant for IdSupportedTAs.
	IdSupportedTAs int64 = 64

	// IdTimeToWait is the integer constant for IdTimeToWait.
	IdTimeToWait int64 = 65

	// IdUEaggregateMaximumBitrate is the integer constant for IdUEaggregateMaximumBitrate.
	IdUEaggregateMaximumBitrate int64 = 66

	// IdTAI is the integer constant for IdTAI.
	IdTAI int64 = 67

	// IdUnknown68 is the integer constant for IdUnknown68.
	IdUnknown68 int64 = 68

	// IdERABReleaseListBearerRelComp is the integer constant for IdERABReleaseListBearerRelComp.
	IdERABReleaseListBearerRelComp int64 = 69

	// IdCdma2000PDU is the integer constant for IdCdma2000PDU.
	IdCdma2000PDU int64 = 70

	// IdCdma2000RATType is the integer constant for IdCdma2000RATType.
	IdCdma2000RATType int64 = 71

	// IdCdma2000SectorID is the integer constant for IdCdma2000SectorID.
	IdCdma2000SectorID int64 = 72

	// IdSecurityKey is the integer constant for IdSecurityKey.
	IdSecurityKey int64 = 73

	// IdUERadioCapability is the integer constant for IdUERadioCapability.
	IdUERadioCapability int64 = 74

	// IdGUMMEIID is the integer constant for IdGUMMEIID.
	IdGUMMEIID int64 = 75

	// IdUnknown76 is the integer constant for IdUnknown76.
	IdUnknown76 int64 = 76

	// IdUnknown77 is the integer constant for IdUnknown77.
	IdUnknown77 int64 = 77

	// IdERABInformationListItem is the integer constant for IdERABInformationListItem.
	IdERABInformationListItem int64 = 78

	// IdDirectForwardingPathAvailability is the integer constant for IdDirectForwardingPathAvailability.
	IdDirectForwardingPathAvailability int64 = 79

	// IdUEIdentityIndexValue is the integer constant for IdUEIdentityIndexValue.
	IdUEIdentityIndexValue int64 = 80

	// IdUnknown81 is the integer constant for IdUnknown81.
	IdUnknown81 int64 = 81

	// IdUnknown82 is the integer constant for IdUnknown82.
	IdUnknown82 int64 = 82

	// IdCdma2000HOStatus is the integer constant for IdCdma2000HOStatus.
	IdCdma2000HOStatus int64 = 83

	// IdCdma2000HORequiredIndication is the integer constant for IdCdma2000HORequiredIndication.
	IdCdma2000HORequiredIndication int64 = 84

	// IdUnknown85 is the integer constant for IdUnknown85.
	IdUnknown85 int64 = 85

	// IdEUTRANTraceID is the integer constant for IdEUTRANTraceID.
	IdEUTRANTraceID int64 = 86

	// IdRelativeMMECapacity is the integer constant for IdRelativeMMECapacity.
	IdRelativeMMECapacity int64 = 87

	// IdSourceMMEUES1APID is the integer constant for IdSourceMMEUES1APID.
	IdSourceMMEUES1APID int64 = 88

	// IdBearersSubjectToStatusTransferItem is the integer constant for IdBearersSubjectToStatusTransferItem.
	IdBearersSubjectToStatusTransferItem int64 = 89

	// IdENBStatusTransferTransparentContainer is the integer constant for IdENBStatusTransferTransparentContainer.
	IdENBStatusTransferTransparentContainer int64 = 90

	// IdUEAssociatedLogicalS1ConnectionItem is the integer constant for IdUEAssociatedLogicalS1ConnectionItem.
	IdUEAssociatedLogicalS1ConnectionItem int64 = 91

	// IdResetType is the integer constant for IdResetType.
	IdResetType int64 = 92

	// IdUEAssociatedLogicalS1ConnectionListResAck is the integer constant for IdUEAssociatedLogicalS1ConnectionListResAck.
	IdUEAssociatedLogicalS1ConnectionListResAck int64 = 93

	// IdERABToBeSwitchedULItem is the integer constant for IdERABToBeSwitchedULItem.
	IdERABToBeSwitchedULItem int64 = 94

	// IdERABToBeSwitchedULList is the integer constant for IdERABToBeSwitchedULList.
	IdERABToBeSwitchedULList int64 = 95

	// IdSTMSI is the integer constant for IdSTMSI.
	IdSTMSI int64 = 96

	// IdCdma2000OneXRAND is the integer constant for IdCdma2000OneXRAND.
	IdCdma2000OneXRAND int64 = 97

	// IdRequestType is the integer constant for IdRequestType.
	IdRequestType int64 = 98

	// IdUES1APIDs is the integer constant for IdUES1APIDs.
	IdUES1APIDs int64 = 99

	// IdEUTRANCGI is the integer constant for IdEUTRANCGI.
	IdEUTRANCGI int64 = 100

	// IdOverloadResponse is the integer constant for IdOverloadResponse.
	IdOverloadResponse int64 = 101

	// IdCdma2000OneXSRVCCInfo is the integer constant for IdCdma2000OneXSRVCCInfo.
	IdCdma2000OneXSRVCCInfo int64 = 102

	// IdERABFailedToBeReleasedList is the integer constant for IdERABFailedToBeReleasedList.
	IdERABFailedToBeReleasedList int64 = 103

	// IdSourceToTargetTransparentContainer is the integer constant for IdSourceToTargetTransparentContainer.
	IdSourceToTargetTransparentContainer int64 = 104

	// IdServedGUMMEIs is the integer constant for IdServedGUMMEIs.
	IdServedGUMMEIs int64 = 105

	// IdSubscriberProfileIDforRFP is the integer constant for IdSubscriberProfileIDforRFP.
	IdSubscriberProfileIDforRFP int64 = 106

	// IdUESecurityCapabilities is the integer constant for IdUESecurityCapabilities.
	IdUESecurityCapabilities int64 = 107

	// IdCSFallbackIndicator is the integer constant for IdCSFallbackIndicator.
	IdCSFallbackIndicator int64 = 108

	// IdCNDomain is the integer constant for IdCNDomain.
	IdCNDomain int64 = 109

	// IdERABReleasedList is the integer constant for IdERABReleasedList.
	IdERABReleasedList int64 = 110

	// IdMessageIdentifier is the integer constant for IdMessageIdentifier.
	IdMessageIdentifier int64 = 111

	// IdSerialNumber is the integer constant for IdSerialNumber.
	IdSerialNumber int64 = 112

	// IdWarningAreaList is the integer constant for IdWarningAreaList.
	IdWarningAreaList int64 = 113

	// IdRepetitionPeriod is the integer constant for IdRepetitionPeriod.
	IdRepetitionPeriod int64 = 114

	// IdNumberofBroadcastRequest is the integer constant for IdNumberofBroadcastRequest.
	IdNumberofBroadcastRequest int64 = 115

	// IdWarningType is the integer constant for IdWarningType.
	IdWarningType int64 = 116

	// IdWarningSecurityInfo is the integer constant for IdWarningSecurityInfo.
	IdWarningSecurityInfo int64 = 117

	// IdDataCodingScheme is the integer constant for IdDataCodingScheme.
	IdDataCodingScheme int64 = 118

	// IdWarningMessageContents is the integer constant for IdWarningMessageContents.
	IdWarningMessageContents int64 = 119

	// IdBroadcastCompletedAreaList is the integer constant for IdBroadcastCompletedAreaList.
	IdBroadcastCompletedAreaList int64 = 120

	// IdInterSystemInformationTransferTypeEDT is the integer constant for IdInterSystemInformationTransferTypeEDT.
	IdInterSystemInformationTransferTypeEDT int64 = 121

	// IdInterSystemInformationTransferTypeMDT is the integer constant for IdInterSystemInformationTransferTypeMDT.
	IdInterSystemInformationTransferTypeMDT int64 = 122

	// IdTargetToSourceTransparentContainer is the integer constant for IdTargetToSourceTransparentContainer.
	IdTargetToSourceTransparentContainer int64 = 123

	// IdSRVCCOperationPossible is the integer constant for IdSRVCCOperationPossible.
	IdSRVCCOperationPossible int64 = 124

	// IdSRVCCHOIndication is the integer constant for IdSRVCCHOIndication.
	IdSRVCCHOIndication int64 = 125

	// IdNASDownlinkCount is the integer constant for IdNASDownlinkCount.
	IdNASDownlinkCount int64 = 126

	// IdCSGId is the integer constant for IdCSGId.
	IdCSGId int64 = 127

	// IdCSGIdList is the integer constant for IdCSGIdList.
	IdCSGIdList int64 = 128

	// IdSONConfigurationTransferECT is the integer constant for IdSONConfigurationTransferECT.
	IdSONConfigurationTransferECT int64 = 129

	// IdSONConfigurationTransferMCT is the integer constant for IdSONConfigurationTransferMCT.
	IdSONConfigurationTransferMCT int64 = 130

	// IdTraceCollectionEntityIPAddress is the integer constant for IdTraceCollectionEntityIPAddress.
	IdTraceCollectionEntityIPAddress int64 = 131

	// IdMSClassmark2 is the integer constant for IdMSClassmark2.
	IdMSClassmark2 int64 = 132

	// IdMSClassmark3 is the integer constant for IdMSClassmark3.
	IdMSClassmark3 int64 = 133

	// IdRRCEstablishmentCause is the integer constant for IdRRCEstablishmentCause.
	IdRRCEstablishmentCause int64 = 134

	// IdNASSecurityParametersfromEUTRAN is the integer constant for IdNASSecurityParametersfromEUTRAN.
	IdNASSecurityParametersfromEUTRAN int64 = 135

	// IdNASSecurityParameterstoEUTRAN is the integer constant for IdNASSecurityParameterstoEUTRAN.
	IdNASSecurityParameterstoEUTRAN int64 = 136

	// IdDefaultPagingDRX is the integer constant for IdDefaultPagingDRX.
	IdDefaultPagingDRX int64 = 137

	// IdSourceToTargetTransparentContainerSecondary is the integer constant for IdSourceToTargetTransparentContainerSecondary.
	IdSourceToTargetTransparentContainerSecondary int64 = 138

	// IdTargetToSourceTransparentContainerSecondary is the integer constant for IdTargetToSourceTransparentContainerSecondary.
	IdTargetToSourceTransparentContainerSecondary int64 = 139

	// IdEUTRANRoundTripDelayEstimationInfo is the integer constant for IdEUTRANRoundTripDelayEstimationInfo.
	IdEUTRANRoundTripDelayEstimationInfo int64 = 140

	// IdBroadcastCancelledAreaList is the integer constant for IdBroadcastCancelledAreaList.
	IdBroadcastCancelledAreaList int64 = 141

	// IdConcurrentWarningMessageIndicator is the integer constant for IdConcurrentWarningMessageIndicator.
	IdConcurrentWarningMessageIndicator int64 = 142

	// IdDataForwardingNotPossible is the integer constant for IdDataForwardingNotPossible.
	IdDataForwardingNotPossible int64 = 143

	// IdExtendedRepetitionPeriod is the integer constant for IdExtendedRepetitionPeriod.
	IdExtendedRepetitionPeriod int64 = 144

	// IdCellAccessMode is the integer constant for IdCellAccessMode.
	IdCellAccessMode int64 = 145

	// IdCSGMembershipStatus is the integer constant for IdCSGMembershipStatus.
	IdCSGMembershipStatus int64 = 146

	// IdLPPaPDU is the integer constant for IdLPPaPDU.
	IdLPPaPDU int64 = 147

	// IdRoutingID is the integer constant for IdRoutingID.
	IdRoutingID int64 = 148

	// IdTimeSynchronisationInfo is the integer constant for IdTimeSynchronisationInfo.
	IdTimeSynchronisationInfo int64 = 149

	// IdPSServiceNotAvailable is the integer constant for IdPSServiceNotAvailable.
	IdPSServiceNotAvailable int64 = 150

	// IdPagingPriority is the integer constant for IdPagingPriority.
	IdPagingPriority int64 = 151

	// IdX2TNLConfigurationInfo is the integer constant for IdX2TNLConfigurationInfo.
	IdX2TNLConfigurationInfo int64 = 152

	// IdENBX2ExtendedTransportLayerAddresses is the integer constant for IdENBX2ExtendedTransportLayerAddresses.
	IdENBX2ExtendedTransportLayerAddresses int64 = 153

	// IdGUMMEIList is the integer constant for IdGUMMEIList.
	IdGUMMEIList int64 = 154

	// IdGWTransportLayerAddress is the integer constant for IdGWTransportLayerAddress.
	IdGWTransportLayerAddress int64 = 155

	// IdCorrelationID is the integer constant for IdCorrelationID.
	IdCorrelationID int64 = 156

	// IdSourceMMEGUMMEI is the integer constant for IdSourceMMEGUMMEI.
	IdSourceMMEGUMMEI int64 = 157

	// IdMMEUES1APID2 is the integer constant for IdMMEUES1APID2.
	IdMMEUES1APID2 int64 = 158

	// IdRegisteredLAI is the integer constant for IdRegisteredLAI.
	IdRegisteredLAI int64 = 159

	// IdRelayNodeIndicator is the integer constant for IdRelayNodeIndicator.
	IdRelayNodeIndicator int64 = 160

	// IdTrafficLoadReductionIndication is the integer constant for IdTrafficLoadReductionIndication.
	IdTrafficLoadReductionIndication int64 = 161

	// IdMDTConfiguration is the integer constant for IdMDTConfiguration.
	IdMDTConfiguration int64 = 162

	// IdMMERelaySupportIndicator is the integer constant for IdMMERelaySupportIndicator.
	IdMMERelaySupportIndicator int64 = 163

	// IdGWContextReleaseIndication is the integer constant for IdGWContextReleaseIndication.
	IdGWContextReleaseIndication int64 = 164

	// IdManagementBasedMDTAllowed is the integer constant for IdManagementBasedMDTAllowed.
	IdManagementBasedMDTAllowed int64 = 165

	// IdPrivacyIndicator is the integer constant for IdPrivacyIndicator.
	IdPrivacyIndicator int64 = 166

	// IdTimeUEStayedInCellEnhancedGranularity is the integer constant for IdTimeUEStayedInCellEnhancedGranularity.
	IdTimeUEStayedInCellEnhancedGranularity int64 = 167

	// IdHOCause is the integer constant for IdHOCause.
	IdHOCause int64 = 168

	// IdVoiceSupportMatchIndicator is the integer constant for IdVoiceSupportMatchIndicator.
	IdVoiceSupportMatchIndicator int64 = 169

	// IdGUMMEIType is the integer constant for IdGUMMEIType.
	IdGUMMEIType int64 = 170

	// IdM3Configuration is the integer constant for IdM3Configuration.
	IdM3Configuration int64 = 171

	// IdM4Configuration is the integer constant for IdM4Configuration.
	IdM4Configuration int64 = 172

	// IdM5Configuration is the integer constant for IdM5Configuration.
	IdM5Configuration int64 = 173

	// IdMDTLocationInfo is the integer constant for IdMDTLocationInfo.
	IdMDTLocationInfo int64 = 174

	// IdMobilityInformation is the integer constant for IdMobilityInformation.
	IdMobilityInformation int64 = 175

	// IdTunnelInformationForBBF is the integer constant for IdTunnelInformationForBBF.
	IdTunnelInformationForBBF int64 = 176

	// IdManagementBasedMDTPLMNList is the integer constant for IdManagementBasedMDTPLMNList.
	IdManagementBasedMDTPLMNList int64 = 177

	// IdSignallingBasedMDTPLMNList is the integer constant for IdSignallingBasedMDTPLMNList.
	IdSignallingBasedMDTPLMNList int64 = 178

	// IdULCOUNTValueExtended is the integer constant for IdULCOUNTValueExtended.
	IdULCOUNTValueExtended int64 = 179

	// IdDLCOUNTValueExtended is the integer constant for IdDLCOUNTValueExtended.
	IdDLCOUNTValueExtended int64 = 180

	// IdReceiveStatusOfULPDCPSDUsExtended is the integer constant for IdReceiveStatusOfULPDCPSDUsExtended.
	IdReceiveStatusOfULPDCPSDUsExtended int64 = 181

	// IdECGIListForRestart is the integer constant for IdECGIListForRestart.
	IdECGIListForRestart int64 = 182

	// IdSIPTOCorrelationID is the integer constant for IdSIPTOCorrelationID.
	IdSIPTOCorrelationID int64 = 183

	// IdSIPTOLGWTransportLayerAddress is the integer constant for IdSIPTOLGWTransportLayerAddress.
	IdSIPTOLGWTransportLayerAddress int64 = 184

	// IdTransportInformation is the integer constant for IdTransportInformation.
	IdTransportInformation int64 = 185

	// IdLHNID is the integer constant for IdLHNID.
	IdLHNID int64 = 186

	// IdAdditionalCSFallbackIndicator is the integer constant for IdAdditionalCSFallbackIndicator.
	IdAdditionalCSFallbackIndicator int64 = 187

	// IdTAIListForRestart is the integer constant for IdTAIListForRestart.
	IdTAIListForRestart int64 = 188

	// IdUserLocationInformation is the integer constant for IdUserLocationInformation.
	IdUserLocationInformation int64 = 189

	// IdEmergencyAreaIDListForRestart is the integer constant for IdEmergencyAreaIDListForRestart.
	IdEmergencyAreaIDListForRestart int64 = 190

	// IdKillAllWarningMessages is the integer constant for IdKillAllWarningMessages.
	IdKillAllWarningMessages int64 = 191

	// IdMaskedIMEISV is the integer constant for IdMaskedIMEISV.
	IdMaskedIMEISV int64 = 192

	// IdENBIndirectX2TransportLayerAddresses is the integer constant for IdENBIndirectX2TransportLayerAddresses.
	IdENBIndirectX2TransportLayerAddresses int64 = 193

	// IdUEHistoryInformationFromTheUE is the integer constant for IdUEHistoryInformationFromTheUE.
	IdUEHistoryInformationFromTheUE int64 = 194

	// IdProSeAuthorized is the integer constant for IdProSeAuthorized.
	IdProSeAuthorized int64 = 195

	// IdExpectedUEBehaviour is the integer constant for IdExpectedUEBehaviour.
	IdExpectedUEBehaviour int64 = 196

	// IdLoggedMBSFNMDT is the integer constant for IdLoggedMBSFNMDT.
	IdLoggedMBSFNMDT int64 = 197

	// IdUERadioCapabilityForPaging is the integer constant for IdUERadioCapabilityForPaging.
	IdUERadioCapabilityForPaging int64 = 198

	// IdERABToBeModifiedListBearerModInd is the integer constant for IdERABToBeModifiedListBearerModInd.
	IdERABToBeModifiedListBearerModInd int64 = 199

	// IdERABToBeModifiedItemBearerModInd is the integer constant for IdERABToBeModifiedItemBearerModInd.
	IdERABToBeModifiedItemBearerModInd int64 = 200

	// IdERABNotToBeModifiedListBearerModInd is the integer constant for IdERABNotToBeModifiedListBearerModInd.
	IdERABNotToBeModifiedListBearerModInd int64 = 201

	// IdERABNotToBeModifiedItemBearerModInd is the integer constant for IdERABNotToBeModifiedItemBearerModInd.
	IdERABNotToBeModifiedItemBearerModInd int64 = 202

	// IdERABModifyListBearerModConf is the integer constant for IdERABModifyListBearerModConf.
	IdERABModifyListBearerModConf int64 = 203

	// IdERABModifyItemBearerModConf is the integer constant for IdERABModifyItemBearerModConf.
	IdERABModifyItemBearerModConf int64 = 204

	// IdERABFailedToModifyListBearerModConf is the integer constant for IdERABFailedToModifyListBearerModConf.
	IdERABFailedToModifyListBearerModConf int64 = 205

	// IdSONInformationReport is the integer constant for IdSONInformationReport.
	IdSONInformationReport int64 = 206

	// IdMutingAvailabilityIndication is the integer constant for IdMutingAvailabilityIndication.
	IdMutingAvailabilityIndication int64 = 207

	// IdMutingPatternInformation is the integer constant for IdMutingPatternInformation.
	IdMutingPatternInformation int64 = 208

	// IdSynchronisationInformation is the integer constant for IdSynchronisationInformation.
	IdSynchronisationInformation int64 = 209

	// IdERABToBeReleasedListBearerModConf is the integer constant for IdERABToBeReleasedListBearerModConf.
	IdERABToBeReleasedListBearerModConf int64 = 210

	// IdAssistanceDataForPaging is the integer constant for IdAssistanceDataForPaging.
	IdAssistanceDataForPaging int64 = 211

	// IdCellIdentifierAndCELevelForCECapableUEs is the integer constant for IdCellIdentifierAndCELevelForCECapableUEs.
	IdCellIdentifierAndCELevelForCECapableUEs int64 = 212

	// IdInformationOnRecommendedCellsAndENBsForPaging is the integer constant for IdInformationOnRecommendedCellsAndENBsForPaging.
	IdInformationOnRecommendedCellsAndENBsForPaging int64 = 213

	// IdRecommendedCellItem is the integer constant for IdRecommendedCellItem.
	IdRecommendedCellItem int64 = 214

	// IdRecommendedENBItem is the integer constant for IdRecommendedENBItem.
	IdRecommendedENBItem int64 = 215

	// IdProSeUEtoNetworkRelaying is the integer constant for IdProSeUEtoNetworkRelaying.
	IdProSeUEtoNetworkRelaying int64 = 216

	// IdULCOUNTValuePDCPSNlength18 is the integer constant for IdULCOUNTValuePDCPSNlength18.
	IdULCOUNTValuePDCPSNlength18 int64 = 217

	// IdDLCOUNTValuePDCPSNlength18 is the integer constant for IdDLCOUNTValuePDCPSNlength18.
	IdDLCOUNTValuePDCPSNlength18 int64 = 218

	// IdReceiveStatusOfULPDCPSDUsPDCPSNlength18 is the integer constant for IdReceiveStatusOfULPDCPSDUsPDCPSNlength18.
	IdReceiveStatusOfULPDCPSDUsPDCPSNlength18 int64 = 219

	// IdM6Configuration is the integer constant for IdM6Configuration.
	IdM6Configuration int64 = 220

	// IdM7Configuration is the integer constant for IdM7Configuration.
	IdM7Configuration int64 = 221

	// IdPWSfailedECGIList is the integer constant for IdPWSfailedECGIList.
	IdPWSfailedECGIList int64 = 222

	// IdMMEGroupID is the integer constant for IdMMEGroupID.
	IdMMEGroupID int64 = 223

	// IdAdditionalGUTI is the integer constant for IdAdditionalGUTI.
	IdAdditionalGUTI int64 = 224

	// IdS1Message is the integer constant for IdS1Message.
	IdS1Message int64 = 225

	// IdCSGMembershipInfo is the integer constant for IdCSGMembershipInfo.
	IdCSGMembershipInfo int64 = 226

	// IdPagingEDRXInformation is the integer constant for IdPagingEDRXInformation.
	IdPagingEDRXInformation int64 = 227

	// IdUERetentionInformation is the integer constant for IdUERetentionInformation.
	IdUERetentionInformation int64 = 228

	// IdUnknown229 is the integer constant for IdUnknown229.
	IdUnknown229 int64 = 229

	// IdUEUsageType is the integer constant for IdUEUsageType.
	IdUEUsageType int64 = 230

	// IdExtendedUEIdentityIndexValue is the integer constant for IdExtendedUEIdentityIndexValue.
	IdExtendedUEIdentityIndexValue int64 = 231

	// IdRATType is the integer constant for IdRATType.
	IdRATType int64 = 232

	// IdBearerType is the integer constant for IdBearerType.
	IdBearerType int64 = 233

	// IdNBIoTDefaultPagingDRX is the integer constant for IdNBIoTDefaultPagingDRX.
	IdNBIoTDefaultPagingDRX int64 = 234

	// IdERABFailedToResumeListResumeReq is the integer constant for IdERABFailedToResumeListResumeReq.
	IdERABFailedToResumeListResumeReq int64 = 235

	// IdERABFailedToResumeItemResumeReq is the integer constant for IdERABFailedToResumeItemResumeReq.
	IdERABFailedToResumeItemResumeReq int64 = 236

	// IdERABFailedToResumeListResumeRes is the integer constant for IdERABFailedToResumeListResumeRes.
	IdERABFailedToResumeListResumeRes int64 = 237

	// IdERABFailedToResumeItemResumeRes is the integer constant for IdERABFailedToResumeItemResumeRes.
	IdERABFailedToResumeItemResumeRes int64 = 238

	// IdNBIoTPagingEDRXInformation is the integer constant for IdNBIoTPagingEDRXInformation.
	IdNBIoTPagingEDRXInformation int64 = 239

	// IdV2XServicesAuthorized is the integer constant for IdV2XServicesAuthorized.
	IdV2XServicesAuthorized int64 = 240

	// IdUEUserPlaneCIoTSupportIndicator is the integer constant for IdUEUserPlaneCIoTSupportIndicator.
	IdUEUserPlaneCIoTSupportIndicator int64 = 241

	// IdCEModeBSupportIndicator is the integer constant for IdCEModeBSupportIndicator.
	IdCEModeBSupportIndicator int64 = 242

	// IdSRVCCOperationNotPossible is the integer constant for IdSRVCCOperationNotPossible.
	IdSRVCCOperationNotPossible int64 = 243

	// IdNBIoTUEIdentityIndexValue is the integer constant for IdNBIoTUEIdentityIndexValue.
	IdNBIoTUEIdentityIndexValue int64 = 244

	// IdRRCResumeCause is the integer constant for IdRRCResumeCause.
	IdRRCResumeCause int64 = 245

	// IdDCNID is the integer constant for IdDCNID.
	IdDCNID int64 = 246

	// IdServedDCNs is the integer constant for IdServedDCNs.
	IdServedDCNs int64 = 247

	// IdUESidelinkAggregateMaximumBitrate is the integer constant for IdUESidelinkAggregateMaximumBitrate.
	IdUESidelinkAggregateMaximumBitrate int64 = 248

	// IdDLNASPDUDeliveryAckRequest is the integer constant for IdDLNASPDUDeliveryAckRequest.
	IdDLNASPDUDeliveryAckRequest int64 = 249

	// IdCoverageLevel is the integer constant for IdCoverageLevel.
	IdCoverageLevel int64 = 250

	// IdEnhancedCoverageRestricted is the integer constant for IdEnhancedCoverageRestricted.
	IdEnhancedCoverageRestricted int64 = 251

	// IdUELevelQoSParameters is the integer constant for IdUELevelQoSParameters.
	IdUELevelQoSParameters int64 = 252

	// IdDLCPSecurityInformation is the integer constant for IdDLCPSecurityInformation.
	IdDLCPSecurityInformation int64 = 253

	// IdULCPSecurityInformation is the integer constant for IdULCPSecurityInformation.
	IdULCPSecurityInformation int64 = 254

	// IdExtendedERABMaximumBitrateDL is the integer constant for IdExtendedERABMaximumBitrateDL.
	IdExtendedERABMaximumBitrateDL int64 = 255

	// IdExtendedERABMaximumBitrateUL is the integer constant for IdExtendedERABMaximumBitrateUL.
	IdExtendedERABMaximumBitrateUL int64 = 256

	// IdExtendedERABGuaranteedBitrateDL is the integer constant for IdExtendedERABGuaranteedBitrateDL.
	IdExtendedERABGuaranteedBitrateDL int64 = 257

	// IdExtendedERABGuaranteedBitrateUL is the integer constant for IdExtendedERABGuaranteedBitrateUL.
	IdExtendedERABGuaranteedBitrateUL int64 = 258

	// IdExtendedUEaggregateMaximumBitRateDL is the integer constant for IdExtendedUEaggregateMaximumBitRateDL.
	IdExtendedUEaggregateMaximumBitRateDL int64 = 259

	// IdExtendedUEaggregateMaximumBitRateUL is the integer constant for IdExtendedUEaggregateMaximumBitRateUL.
	IdExtendedUEaggregateMaximumBitRateUL int64 = 260

	// IdNRrestrictioninEPSasSecondaryRAT is the integer constant for IdNRrestrictioninEPSasSecondaryRAT.
	IdNRrestrictioninEPSasSecondaryRAT int64 = 261

	// IdUEAppLayerMeasConfig is the integer constant for IdUEAppLayerMeasConfig.
	IdUEAppLayerMeasConfig int64 = 262

	// IdUEApplicationLayerMeasurementCapability is the integer constant for IdUEApplicationLayerMeasurementCapability.
	IdUEApplicationLayerMeasurementCapability int64 = 263

	// IdSecondaryRATDataUsageReportList is the integer constant for IdSecondaryRATDataUsageReportList.
	IdSecondaryRATDataUsageReportList int64 = 264

	// IdSecondaryRATDataUsageReportItem is the integer constant for IdSecondaryRATDataUsageReportItem.
	IdSecondaryRATDataUsageReportItem int64 = 265

	// IdHandoverFlag is the integer constant for IdHandoverFlag.
	IdHandoverFlag int64 = 266

	// IdERABUsageReportItem is the integer constant for IdERABUsageReportItem.
	IdERABUsageReportItem int64 = 267

	// IdSecondaryRATDataUsageRequest is the integer constant for IdSecondaryRATDataUsageRequest.
	IdSecondaryRATDataUsageRequest int64 = 268

	// IdNRUESecurityCapabilities is the integer constant for IdNRUESecurityCapabilities.
	IdNRUESecurityCapabilities int64 = 269

	// IdUnlicensedSpectrumRestriction is the integer constant for IdUnlicensedSpectrumRestriction.
	IdUnlicensedSpectrumRestriction int64 = 270

	// IdCEModeBRestricted is the integer constant for IdCEModeBRestricted.
	IdCEModeBRestricted int64 = 271

	// IdLTEMIndication is the integer constant for IdLTEMIndication.
	IdLTEMIndication int64 = 272

	// IdDownlinkPacketLossRate is the integer constant for IdDownlinkPacketLossRate.
	IdDownlinkPacketLossRate int64 = 273

	// IdUplinkPacketLossRate is the integer constant for IdUplinkPacketLossRate.
	IdUplinkPacketLossRate int64 = 274

	// IdUECapabilityInfoRequest is the integer constant for IdUECapabilityInfoRequest.
	IdUECapabilityInfoRequest int64 = 275

	// IdServiceType is the integer constant for IdServiceType.
	IdServiceType int64 = 276

	// IdAerialUEsubscriptionInformation is the integer constant for IdAerialUEsubscriptionInformation.
	IdAerialUEsubscriptionInformation int64 = 277

	// IdSubscriptionBasedUEDifferentiationInfo is the integer constant for IdSubscriptionBasedUEDifferentiationInfo.
	IdSubscriptionBasedUEDifferentiationInfo int64 = 278

	// IdUnknown279 is the integer constant for IdUnknown279.
	IdUnknown279 int64 = 279

	// IdEndIndication is the integer constant for IdEndIndication.
	IdEndIndication int64 = 280

	// IdEDTSession is the integer constant for IdEDTSession.
	IdEDTSession int64 = 281

	// IdCNTypeRestrictions is the integer constant for IdCNTypeRestrictions.
	IdCNTypeRestrictions int64 = 282

	// IdPendingDataIndication is the integer constant for IdPendingDataIndication.
	IdPendingDataIndication int64 = 283

	// IdBluetoothMeasurementConfiguration is the integer constant for IdBluetoothMeasurementConfiguration.
	IdBluetoothMeasurementConfiguration int64 = 284

	// IdWLANMeasurementConfiguration is the integer constant for IdWLANMeasurementConfiguration.
	IdWLANMeasurementConfiguration int64 = 285

	// IdWarningAreaCoordinates is the integer constant for IdWarningAreaCoordinates.
	IdWarningAreaCoordinates int64 = 286

	// IdNRrestrictionin5GS is the integer constant for IdNRrestrictionin5GS.
	IdNRrestrictionin5GS int64 = 287

	// IdPSCellInformation is the integer constant for IdPSCellInformation.
	IdPSCellInformation int64 = 288

	// IdUnknown289 is the integer constant for IdUnknown289.
	IdUnknown289 int64 = 289

	// IdLastNGRANPLMNIdentity is the integer constant for IdLastNGRANPLMNIdentity.
	IdLastNGRANPLMNIdentity int64 = 290

	// IdConnectedengNBList is the integer constant for IdConnectedengNBList.
	IdConnectedengNBList int64 = 291

	// IdConnectedengNBToAddList is the integer constant for IdConnectedengNBToAddList.
	IdConnectedengNBToAddList int64 = 292

	// IdConnectedengNBToRemoveList is the integer constant for IdConnectedengNBToRemoveList.
	IdConnectedengNBToRemoveList int64 = 293

	// IdENDCSONConfigurationTransferECT is the integer constant for IdENDCSONConfigurationTransferECT.
	IdENDCSONConfigurationTransferECT int64 = 294

	// IdENDCSONConfigurationTransferMCT is the integer constant for IdENDCSONConfigurationTransferMCT.
	IdENDCSONConfigurationTransferMCT int64 = 295

	// IdIMSvoiceEPSfallbackfrom5G is the integer constant for IdIMSvoiceEPSfallbackfrom5G.
	IdIMSvoiceEPSfallbackfrom5G int64 = 296

	// IdTimeSinceSecondaryNodeRelease is the integer constant for IdTimeSinceSecondaryNodeRelease.
	IdTimeSinceSecondaryNodeRelease int64 = 297

	// IdRequestTypeAdditionalInfo is the integer constant for IdRequestTypeAdditionalInfo.
	IdRequestTypeAdditionalInfo int64 = 298

	// IdAdditionalRRMPriorityIndex is the integer constant for IdAdditionalRRMPriorityIndex.
	IdAdditionalRRMPriorityIndex int64 = 299

	// IdContextatSource is the integer constant for IdContextatSource.
	IdContextatSource int64 = 300

	// IdIABAuthorized is the integer constant for IdIABAuthorized.
	IdIABAuthorized int64 = 301

	// IdIABNodeIndication is the integer constant for IdIABNodeIndication.
	IdIABNodeIndication int64 = 302

	// IdIABSupported is the integer constant for IdIABSupported.
	IdIABSupported int64 = 303

	// IdDataSize is the integer constant for IdDataSize.
	IdDataSize int64 = 304

	// IdEthernetType is the integer constant for IdEthernetType.
	IdEthernetType int64 = 305

	// IdNRV2XServicesAuthorized is the integer constant for IdNRV2XServicesAuthorized.
	IdNRV2XServicesAuthorized int64 = 306

	// IdNRUESidelinkAggregateMaximumBitrate is the integer constant for IdNRUESidelinkAggregateMaximumBitrate.
	IdNRUESidelinkAggregateMaximumBitrate int64 = 307

	// IdPC5QoSParameters is the integer constant for IdPC5QoSParameters.
	IdPC5QoSParameters int64 = 308

	// IdIntersystemSONConfigurationTransferMCT is the integer constant for IdIntersystemSONConfigurationTransferMCT.
	IdIntersystemSONConfigurationTransferMCT int64 = 309

	// IdIntersystemSONConfigurationTransferECT is the integer constant for IdIntersystemSONConfigurationTransferECT.
	IdIntersystemSONConfigurationTransferECT int64 = 310

	// IdIntersystemMeasurementConfiguration is the integer constant for IdIntersystemMeasurementConfiguration.
	IdIntersystemMeasurementConfiguration int64 = 311

	// IdSourceNodeID is the integer constant for IdSourceNodeID.
	IdSourceNodeID int64 = 312

	// IdNBIoTRLFReportContainer is the integer constant for IdNBIoTRLFReportContainer.
	IdNBIoTRLFReportContainer int64 = 313

	// IdUERadioCapabilityID is the integer constant for IdUERadioCapabilityID.
	IdUERadioCapabilityID int64 = 314

	// IdUERadioCapabilityNRFormat is the integer constant for IdUERadioCapabilityNRFormat.
	IdUERadioCapabilityNRFormat int64 = 315

	// IdMDTConfigurationNR is the integer constant for IdMDTConfigurationNR.
	IdMDTConfigurationNR int64 = 316

	// IdDAPSRequestInfo is the integer constant for IdDAPSRequestInfo.
	IdDAPSRequestInfo int64 = 317

	// IdDAPSResponseInfoList is the integer constant for IdDAPSResponseInfoList.
	IdDAPSResponseInfoList int64 = 318

	// IdDAPSResponseInfoItem is the integer constant for IdDAPSResponseInfoItem.
	IdDAPSResponseInfoItem int64 = 319

	// IdNotifySourceeNB is the integer constant for IdNotifySourceeNB.
	IdNotifySourceeNB int64 = 320

	// IdENBEarlyStatusTransferTransparentContainer is the integer constant for IdENBEarlyStatusTransferTransparentContainer.
	IdENBEarlyStatusTransferTransparentContainer int64 = 321

	// IdBearersSubjectToEarlyStatusTransferItem is the integer constant for IdBearersSubjectToEarlyStatusTransferItem.
	IdBearersSubjectToEarlyStatusTransferItem int64 = 322

	// IdWUSAssistanceInformation is the integer constant for IdWUSAssistanceInformation.
	IdWUSAssistanceInformation int64 = 323

	// IdNBIoTPagingDRX is the integer constant for IdNBIoTPagingDRX.
	IdNBIoTPagingDRX int64 = 324

	// IdTraceCollectionEntityURI is the integer constant for IdTraceCollectionEntityURI.
	IdTraceCollectionEntityURI int64 = 325

	// IdEmergencyIndicator is the integer constant for IdEmergencyIndicator.
	IdEmergencyIndicator int64 = 326

	// IdUERadioCapabilityForPagingNRFormat is the integer constant for IdUERadioCapabilityForPagingNRFormat.
	IdUERadioCapabilityForPagingNRFormat int64 = 327

	// IdSourceTransportLayerAddress is the integer constant for IdSourceTransportLayerAddress.
	IdSourceTransportLayerAddress int64 = 328

	// IdLastVisitedPSCellList is the integer constant for IdLastVisitedPSCellList.
	IdLastVisitedPSCellList int64 = 329

	// IdRACSIndication is the integer constant for IdRACSIndication.
	IdRACSIndication int64 = 330

	// IdPagingCause is the integer constant for IdPagingCause.
	IdPagingCause int64 = 331

	// IdSecurityIndication is the integer constant for IdSecurityIndication.
	IdSecurityIndication int64 = 332

	// IdSecurityResult is the integer constant for IdSecurityResult.
	IdSecurityResult int64 = 333

	// IdERABSecurityResultItem is the integer constant for IdERABSecurityResultItem.
	IdERABSecurityResultItem int64 = 334

	// IdERABSecurityResultList is the integer constant for IdERABSecurityResultList.
	IdERABSecurityResultList int64 = 335

	// IdRATRestrictions is the integer constant for IdRATRestrictions.
	IdRATRestrictions int64 = 336

	// IdUEContextReferenceatSourceeNB is the integer constant for IdUEContextReferenceatSourceeNB.
	IdUEContextReferenceatSourceeNB int64 = 337

	// IdUnknown338 is the integer constant for IdUnknown338.
	IdUnknown338 int64 = 338

	// IdLTENTNTAIInformation is the integer constant for IdLTENTNTAIInformation.
	IdLTENTNTAIInformation int64 = 339

	// IdSourceNodeTransportLayerAddress is the integer constant for IdSourceNodeTransportLayerAddress.
	IdSourceNodeTransportLayerAddress int64 = 340

	// IdERABToBeUpdatedList is the integer constant for IdERABToBeUpdatedList.
	IdERABToBeUpdatedList int64 = 341

	// IdERABToBeUpdatedItem is the integer constant for IdERABToBeUpdatedItem.
	IdERABToBeUpdatedItem int64 = 342

	// IdSourceSNID is the integer constant for IdSourceSNID.
	IdSourceSNID int64 = 343

	// IdLoggedMDTTrigger is the integer constant for IdLoggedMDTTrigger.
	IdLoggedMDTTrigger int64 = 344

	// IdSensorMeasurementConfiguration is the integer constant for IdSensorMeasurementConfiguration.
	IdSensorMeasurementConfiguration int64 = 345

	// IdM4ReportAmount is the integer constant for IdM4ReportAmount.
	IdM4ReportAmount int64 = 346

	// IdM5ReportAmount is the integer constant for IdM5ReportAmount.
	IdM5ReportAmount int64 = 347

	// IdM6ReportAmount is the integer constant for IdM6ReportAmount.
	IdM6ReportAmount int64 = 348

	// IdM7ReportAmount is the integer constant for IdM7ReportAmount.
	IdM7ReportAmount int64 = 349

	// IdTimeBasedHandoverInformation is the integer constant for IdTimeBasedHandoverInformation.
	IdTimeBasedHandoverInformation int64 = 350

	// IdBearersSubjectToDLDiscardingItem is the integer constant for IdBearersSubjectToDLDiscardingItem.
	IdBearersSubjectToDLDiscardingItem int64 = 351

	// IdBearersSubjectToDLDiscardingList is the integer constant for IdBearersSubjectToDLDiscardingList.
	IdBearersSubjectToDLDiscardingList int64 = 352

	// IdCoarseUELocationRequested is the integer constant for IdCoarseUELocationRequested.
	IdCoarseUELocationRequested int64 = 353

	// IdCoarseUELocation is the integer constant for IdCoarseUELocation.
	IdCoarseUELocation int64 = 354

	// IdTimeRefDistribution is the integer constant for IdTimeRefDistribution.
	IdTimeRefDistribution int64 = 355

	// IdRequestedTNLInfo is the integer constant for IdRequestedTNLInfo.
	IdRequestedTNLInfo int64 = 356
)
