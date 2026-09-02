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

	// IdHandoverPreparation is the integer constant for id-HandoverPreparation.
	IdHandoverPreparation int64 = 0

	// IdHandoverResourceAllocation is the integer constant for id-HandoverResourceAllocation.
	IdHandoverResourceAllocation int64 = 1

	// IdHandoverNotification is the integer constant for id-HandoverNotification.
	IdHandoverNotification int64 = 2

	// IdPathSwitchRequest is the integer constant for id-PathSwitchRequest.
	IdPathSwitchRequest int64 = 3

	// IdHandoverCancel is the integer constant for id-HandoverCancel.
	IdHandoverCancel int64 = 4

	// IdERABSetup is the integer constant for id-E-RABSetup.
	IdERABSetup int64 = 5

	// IdERABModify is the integer constant for id-E-RABModify.
	IdERABModify int64 = 6

	// IdERABRelease is the integer constant for id-E-RABRelease.
	IdERABRelease int64 = 7

	// IdERABReleaseIndication is the integer constant for id-E-RABReleaseIndication.
	IdERABReleaseIndication int64 = 8

	// IdInitialContextSetup is the integer constant for id-InitialContextSetup.
	IdInitialContextSetup int64 = 9

	// IdPaging is the integer constant for id-Paging.
	IdPaging int64 = 10

	// IdDownlinkNASTransport is the integer constant for id-downlinkNASTransport.
	IdDownlinkNASTransport int64 = 11

	// IdInitialUEMessage is the integer constant for id-initialUEMessage.
	IdInitialUEMessage int64 = 12

	// IdUplinkNASTransport is the integer constant for id-uplinkNASTransport.
	IdUplinkNASTransport int64 = 13

	// IdReset is the integer constant for id-Reset.
	IdReset int64 = 14

	// IdErrorIndication is the integer constant for id-ErrorIndication.
	IdErrorIndication int64 = 15

	// IdNASNonDeliveryIndication is the integer constant for id-NASNonDeliveryIndication.
	IdNASNonDeliveryIndication int64 = 16

	// IdS1Setup is the integer constant for id-S1Setup.
	IdS1Setup int64 = 17

	// IdUEContextReleaseRequest is the integer constant for id-UEContextReleaseRequest.
	IdUEContextReleaseRequest int64 = 18

	// IdDownlinkS1cdma2000tunnelling is the integer constant for id-DownlinkS1cdma2000tunnelling.
	IdDownlinkS1cdma2000tunnelling int64 = 19

	// IdUplinkS1cdma2000tunnelling is the integer constant for id-UplinkS1cdma2000tunnelling.
	IdUplinkS1cdma2000tunnelling int64 = 20

	// IdUEContextModification is the integer constant for id-UEContextModification.
	IdUEContextModification int64 = 21

	// IdUECapabilityInfoIndication is the integer constant for id-UECapabilityInfoIndication.
	IdUECapabilityInfoIndication int64 = 22

	// IdUEContextRelease is the integer constant for id-UEContextRelease.
	IdUEContextRelease int64 = 23

	// IdENBStatusTransfer is the integer constant for id-eNBStatusTransfer.
	IdENBStatusTransfer int64 = 24

	// IdMMEStatusTransfer is the integer constant for id-MMEStatusTransfer.
	IdMMEStatusTransfer int64 = 25

	// IdDeactivateTrace is the integer constant for id-DeactivateTrace.
	IdDeactivateTrace int64 = 26

	// IdTraceStart is the integer constant for id-TraceStart.
	IdTraceStart int64 = 27

	// IdTraceFailureIndication is the integer constant for id-TraceFailureIndication.
	IdTraceFailureIndication int64 = 28

	// IdENBConfigurationUpdate is the integer constant for id-ENBConfigurationUpdate.
	IdENBConfigurationUpdate int64 = 29

	// IdMMEConfigurationUpdate is the integer constant for id-MMEConfigurationUpdate.
	IdMMEConfigurationUpdate int64 = 30

	// IdLocationReportingControl is the integer constant for id-LocationReportingControl.
	IdLocationReportingControl int64 = 31

	// IdLocationReportingFailureIndication is the integer constant for id-LocationReportingFailureIndication.
	IdLocationReportingFailureIndication int64 = 32

	// IdLocationReport is the integer constant for id-LocationReport.
	IdLocationReport int64 = 33

	// IdOverloadStart is the integer constant for id-OverloadStart.
	IdOverloadStart int64 = 34

	// IdOverloadStop is the integer constant for id-OverloadStop.
	IdOverloadStop int64 = 35

	// IdWriteReplaceWarning is the integer constant for id-WriteReplaceWarning.
	IdWriteReplaceWarning int64 = 36

	// IdENBDirectInformationTransfer is the integer constant for id-eNBDirectInformationTransfer.
	IdENBDirectInformationTransfer int64 = 37

	// IdMMEDirectInformationTransfer is the integer constant for id-MMEDirectInformationTransfer.
	IdMMEDirectInformationTransfer int64 = 38

	// IdPrivateMessage is the integer constant for id-PrivateMessage.
	IdPrivateMessage int64 = 39

	// IdENBConfigurationTransfer is the integer constant for id-eNBConfigurationTransfer.
	IdENBConfigurationTransfer int64 = 40

	// IdMMEConfigurationTransfer is the integer constant for id-MMEConfigurationTransfer.
	IdMMEConfigurationTransfer int64 = 41

	// IdCellTrafficTrace is the integer constant for id-CellTrafficTrace.
	IdCellTrafficTrace int64 = 42

	// IdKill is the integer constant for id-Kill.
	IdKill int64 = 43

	// IdDownlinkUEAssociatedLPPaTransport is the integer constant for id-downlinkUEAssociatedLPPaTransport.
	IdDownlinkUEAssociatedLPPaTransport int64 = 44

	// IdUplinkUEAssociatedLPPaTransport is the integer constant for id-uplinkUEAssociatedLPPaTransport.
	IdUplinkUEAssociatedLPPaTransport int64 = 45

	// IdDownlinkNonUEAssociatedLPPaTransport is the integer constant for id-downlinkNonUEAssociatedLPPaTransport.
	IdDownlinkNonUEAssociatedLPPaTransport int64 = 46

	// IdUplinkNonUEAssociatedLPPaTransport is the integer constant for id-uplinkNonUEAssociatedLPPaTransport.
	IdUplinkNonUEAssociatedLPPaTransport int64 = 47

	// IdUERadioCapabilityMatch is the integer constant for id-UERadioCapabilityMatch.
	IdUERadioCapabilityMatch int64 = 48

	// IdPWSRestartIndication is the integer constant for id-PWSRestartIndication.
	IdPWSRestartIndication int64 = 49

	// IdERABModificationIndication is the integer constant for id-E-RABModificationIndication.
	IdERABModificationIndication int64 = 50

	// IdPWSFailureIndication is the integer constant for id-PWSFailureIndication.
	IdPWSFailureIndication int64 = 51

	// IdRerouteNASRequest is the integer constant for id-RerouteNASRequest.
	IdRerouteNASRequest int64 = 52

	// IdUEContextModificationIndication is the integer constant for id-UEContextModificationIndication.
	IdUEContextModificationIndication int64 = 53

	// IdConnectionEstablishmentIndication is the integer constant for id-ConnectionEstablishmentIndication.
	IdConnectionEstablishmentIndication int64 = 54

	// IdUEContextSuspend is the integer constant for id-UEContextSuspend.
	IdUEContextSuspend int64 = 55

	// IdUEContextResume is the integer constant for id-UEContextResume.
	IdUEContextResume int64 = 56

	// IdNASDeliveryIndication is the integer constant for id-NASDeliveryIndication.
	IdNASDeliveryIndication int64 = 57

	// IdRetrieveUEInformation is the integer constant for id-RetrieveUEInformation.
	IdRetrieveUEInformation int64 = 58

	// IdUEInformationTransfer is the integer constant for id-UEInformationTransfer.
	IdUEInformationTransfer int64 = 59

	// IdENBCPRelocationIndication is the integer constant for id-eNBCPRelocationIndication.
	IdENBCPRelocationIndication int64 = 60

	// IdMMECPRelocationIndication is the integer constant for id-MMECPRelocationIndication.
	IdMMECPRelocationIndication int64 = 61

	// IdSecondaryRATDataUsageReport is the integer constant for id-SecondaryRATDataUsageReport.
	IdSecondaryRATDataUsageReport int64 = 62

	// IdUERadioCapabilityIDMapping is the integer constant for id-UERadioCapabilityIDMapping.
	IdUERadioCapabilityIDMapping int64 = 63

	// IdHandoverSuccess is the integer constant for id-HandoverSuccess.
	IdHandoverSuccess int64 = 64

	// IdENBEarlyStatusTransfer is the integer constant for id-eNBEarlyStatusTransfer.
	IdENBEarlyStatusTransfer int64 = 65

	// IdMMEEarlyStatusTransfer is the integer constant for id-MMEEarlyStatusTransfer.
	IdMMEEarlyStatusTransfer int64 = 66

	// IdS1Removal is the integer constant for id-S1Removal.
	IdS1Removal int64 = 67

	// MaxPrivateIEs is the integer constant for maxPrivateIEs.
	MaxPrivateIEs int64 = 65535

	// MaxProtocolExtensions is the integer constant for maxProtocolExtensions.
	MaxProtocolExtensions int64 = 65535

	// MaxProtocolIEs is the integer constant for maxProtocolIEs.
	MaxProtocolIEs int64 = 65535

	// MaxnoofCSGs is the integer constant for maxnoofCSGs.
	MaxnoofCSGs int64 = 256

	// MaxnoofERABs is the integer constant for maxnoofE-RABs.
	MaxnoofERABs int64 = 256

	// MaxnoofTAIs is the integer constant for maxnoofTAIs.
	MaxnoofTAIs int64 = 256

	// MaxnoofTACs is the integer constant for maxnoofTACs.
	MaxnoofTACs int64 = 256

	// MaxnoofErrors is the integer constant for maxnoofErrors.
	MaxnoofErrors int64 = 256

	// MaxnoofBPLMNs is the integer constant for maxnoofBPLMNs.
	MaxnoofBPLMNs int64 = 6

	// MaxnoofPLMNsPerMME is the integer constant for maxnoofPLMNsPerMME.
	MaxnoofPLMNsPerMME int64 = 32

	// MaxnoofEPLMNs is the integer constant for maxnoofEPLMNs.
	MaxnoofEPLMNs int64 = 15

	// MaxnoofEPLMNsPlusOne is the integer constant for maxnoofEPLMNsPlusOne.
	MaxnoofEPLMNsPlusOne int64 = 16

	// MaxnoofForbLACs is the integer constant for maxnoofForbLACs.
	MaxnoofForbLACs int64 = 4096

	// MaxnoofForbTACs is the integer constant for maxnoofForbTACs.
	MaxnoofForbTACs int64 = 4096

	// MaxnoofIndividualS1ConnectionsToReset is the integer constant for maxnoofIndividualS1ConnectionsToReset.
	MaxnoofIndividualS1ConnectionsToReset int64 = 256

	// MaxnoofCellsinUEHistoryInfo is the integer constant for maxnoofCellsinUEHistoryInfo.
	MaxnoofCellsinUEHistoryInfo int64 = 16

	// MaxnoofCellsineNB is the integer constant for maxnoofCellsineNB.
	MaxnoofCellsineNB int64 = 256

	// MaxnoofTAIforWarning is the integer constant for maxnoofTAIforWarning.
	MaxnoofTAIforWarning int64 = 65535

	// MaxnoofCellID is the integer constant for maxnoofCellID.
	MaxnoofCellID int64 = 65535

	// MaxnoofDCNs is the integer constant for maxnoofDCNs.
	MaxnoofDCNs int64 = 32

	// MaxnoofEmergencyAreaID is the integer constant for maxnoofEmergencyAreaID.
	MaxnoofEmergencyAreaID int64 = 65535

	// MaxnoofCellinTAI is the integer constant for maxnoofCellinTAI.
	MaxnoofCellinTAI int64 = 65535

	// MaxnoofCellinEAI is the integer constant for maxnoofCellinEAI.
	MaxnoofCellinEAI int64 = 65535

	// MaxnoofeNBX2TLAs is the integer constant for maxnoofeNBX2TLAs.
	MaxnoofeNBX2TLAs int64 = 2

	// MaxnoofeNBX2ExtTLAs is the integer constant for maxnoofeNBX2ExtTLAs.
	MaxnoofeNBX2ExtTLAs int64 = 16

	// MaxnoofeNBX2GTPTLAs is the integer constant for maxnoofeNBX2GTPTLAs.
	MaxnoofeNBX2GTPTLAs int64 = 16

	// MaxnoofRATs is the integer constant for maxnoofRATs.
	MaxnoofRATs int64 = 8

	// MaxnoofGroupIDs is the integer constant for maxnoofGroupIDs.
	MaxnoofGroupIDs int64 = 65535

	// MaxnoofMMECs is the integer constant for maxnoofMMECs.
	MaxnoofMMECs int64 = 256

	// MaxnoofCellIDforMDT is the integer constant for maxnoofCellIDforMDT.
	MaxnoofCellIDforMDT int64 = 32

	// MaxnoofTAforMDT is the integer constant for maxnoofTAforMDT.
	MaxnoofTAforMDT int64 = 8

	// MaxnoofMDTPLMNs is the integer constant for maxnoofMDTPLMNs.
	MaxnoofMDTPLMNs int64 = 16

	// MaxnoofCellsforRestart is the integer constant for maxnoofCellsforRestart.
	MaxnoofCellsforRestart int64 = 256

	// MaxnoofRestartTAIs is the integer constant for maxnoofRestartTAIs.
	MaxnoofRestartTAIs int64 = 2048

	// MaxnoofRestartEmergencyAreaIDs is the integer constant for maxnoofRestartEmergencyAreaIDs.
	MaxnoofRestartEmergencyAreaIDs int64 = 256

	// MaxEARFCN is the integer constant for maxEARFCN.
	MaxEARFCN int64 = 262143

	// MaxnoofMBSFNAreaMDT is the integer constant for maxnoofMBSFNAreaMDT.
	MaxnoofMBSFNAreaMDT int64 = 8

	// MaxnoofRecommendedCells is the integer constant for maxnoofRecommendedCells.
	MaxnoofRecommendedCells int64 = 16

	// MaxnoofRecommendedENBs is the integer constant for maxnoofRecommendedENBs.
	MaxnoofRecommendedENBs int64 = 16

	// Maxnooftimeperiods is the integer constant for maxnooftimeperiods.
	Maxnooftimeperiods int64 = 2

	// MaxnoofCellIDforQMC is the integer constant for maxnoofCellIDforQMC.
	MaxnoofCellIDforQMC int64 = 32

	// MaxnoofTAforQMC is the integer constant for maxnoofTAforQMC.
	MaxnoofTAforQMC int64 = 8

	// MaxnoofPLMNforQMC is the integer constant for maxnoofPLMNforQMC.
	MaxnoofPLMNforQMC int64 = 16

	// MaxnoofBluetoothName is the integer constant for maxnoofBluetoothName.
	MaxnoofBluetoothName int64 = 4

	// MaxnoofWLANName is the integer constant for maxnoofWLANName.
	MaxnoofWLANName int64 = 4

	// MaxnoofConnectedengNBs is the integer constant for maxnoofConnectedengNBs.
	MaxnoofConnectedengNBs int64 = 256

	// MaxnoofPC5QoSFlows is the integer constant for maxnoofPC5QoSFlows.
	MaxnoofPC5QoSFlows int64 = 2048

	// Maxnooffrequencies is the integer constant for maxnooffrequencies.
	Maxnooffrequencies int64 = 64

	// MaxNARFCN is the integer constant for maxNARFCN.
	MaxNARFCN int64 = 3.279165e+06

	// MaxRSIndexCellQual is the integer constant for maxRS-IndexCellQual.
	MaxRSIndexCellQual int64 = 16

	// MaxnoofPSCellsPerPrimaryCellinUEHistoryInfo is the integer constant for maxnoofPSCellsPerPrimaryCellinUEHistoryInfo.
	MaxnoofPSCellsPerPrimaryCellinUEHistoryInfo int64 = 8

	// MaxnoofTACsInNTN is the integer constant for maxnoofTACsInNTN.
	MaxnoofTACsInNTN int64 = 12

	// MaxnoofSensorName is the integer constant for maxnoofSensorName.
	MaxnoofSensorName int64 = 3

	// IdMMEUES1APID is the integer constant for id-MME-UE-S1AP-ID.
	IdMMEUES1APID int64 = 0

	// IdHandoverType is the integer constant for id-HandoverType.
	IdHandoverType int64 = 1

	// IdCause is the integer constant for id-Cause.
	IdCause int64 = 2

	// IdSourceID is the integer constant for id-SourceID.
	IdSourceID int64 = 3

	// IdTargetID is the integer constant for id-TargetID.
	IdTargetID int64 = 4

	// IdUnknown5 is the integer constant for id-Unknown-5.
	IdUnknown5 int64 = 5

	// IdUnknown6 is the integer constant for id-Unknown-6.
	IdUnknown6 int64 = 6

	// IdUnknown7 is the integer constant for id-Unknown-7.
	IdUnknown7 int64 = 7

	// IdENBUES1APID is the integer constant for id-eNB-UE-S1AP-ID.
	IdENBUES1APID int64 = 8

	// IdUnknown9 is the integer constant for id-Unknown-9.
	IdUnknown9 int64 = 9

	// IdUnknown10 is the integer constant for id-Unknown-10.
	IdUnknown10 int64 = 10

	// IdUnknown11 is the integer constant for id-Unknown-11.
	IdUnknown11 int64 = 11

	// IdERABSubjecttoDataForwardingList is the integer constant for id-E-RABSubjecttoDataForwardingList.
	IdERABSubjecttoDataForwardingList int64 = 12

	// IdERABtoReleaseListHOCmd is the integer constant for id-E-RABtoReleaseListHOCmd.
	IdERABtoReleaseListHOCmd int64 = 13

	// IdERABDataForwardingItem is the integer constant for id-E-RABDataForwardingItem.
	IdERABDataForwardingItem int64 = 14

	// IdERABReleaseItemBearerRelComp is the integer constant for id-E-RABReleaseItemBearerRelComp.
	IdERABReleaseItemBearerRelComp int64 = 15

	// IdERABToBeSetupListBearerSUReq is the integer constant for id-E-RABToBeSetupListBearerSUReq.
	IdERABToBeSetupListBearerSUReq int64 = 16

	// IdERABToBeSetupItemBearerSUReq is the integer constant for id-E-RABToBeSetupItemBearerSUReq.
	IdERABToBeSetupItemBearerSUReq int64 = 17

	// IdERABAdmittedList is the integer constant for id-E-RABAdmittedList.
	IdERABAdmittedList int64 = 18

	// IdERABFailedToSetupListHOReqAck is the integer constant for id-E-RABFailedToSetupListHOReqAck.
	IdERABFailedToSetupListHOReqAck int64 = 19

	// IdERABAdmittedItem is the integer constant for id-E-RABAdmittedItem.
	IdERABAdmittedItem int64 = 20

	// IdERABFailedtoSetupItemHOReqAck is the integer constant for id-E-RABFailedtoSetupItemHOReqAck.
	IdERABFailedtoSetupItemHOReqAck int64 = 21

	// IdERABToBeSwitchedDLList is the integer constant for id-E-RABToBeSwitchedDLList.
	IdERABToBeSwitchedDLList int64 = 22

	// IdERABToBeSwitchedDLItem is the integer constant for id-E-RABToBeSwitchedDLItem.
	IdERABToBeSwitchedDLItem int64 = 23

	// IdERABToBeSetupListCtxtSUReq is the integer constant for id-E-RABToBeSetupListCtxtSUReq.
	IdERABToBeSetupListCtxtSUReq int64 = 24

	// IdTraceActivation is the integer constant for id-TraceActivation.
	IdTraceActivation int64 = 25

	// IdNASPDU is the integer constant for id-NAS-PDU.
	IdNASPDU int64 = 26

	// IdERABToBeSetupItemHOReq is the integer constant for id-E-RABToBeSetupItemHOReq.
	IdERABToBeSetupItemHOReq int64 = 27

	// IdERABSetupListBearerSURes is the integer constant for id-E-RABSetupListBearerSURes.
	IdERABSetupListBearerSURes int64 = 28

	// IdERABFailedToSetupListBearerSURes is the integer constant for id-E-RABFailedToSetupListBearerSURes.
	IdERABFailedToSetupListBearerSURes int64 = 29

	// IdERABToBeModifiedListBearerModReq is the integer constant for id-E-RABToBeModifiedListBearerModReq.
	IdERABToBeModifiedListBearerModReq int64 = 30

	// IdERABModifyListBearerModRes is the integer constant for id-E-RABModifyListBearerModRes.
	IdERABModifyListBearerModRes int64 = 31

	// IdERABFailedToModifyList is the integer constant for id-E-RABFailedToModifyList.
	IdERABFailedToModifyList int64 = 32

	// IdERABToBeReleasedList is the integer constant for id-E-RABToBeReleasedList.
	IdERABToBeReleasedList int64 = 33

	// IdERABFailedToReleaseList is the integer constant for id-E-RABFailedToReleaseList.
	IdERABFailedToReleaseList int64 = 34

	// IdERABItem is the integer constant for id-E-RABItem.
	IdERABItem int64 = 35

	// IdERABToBeModifiedItemBearerModReq is the integer constant for id-E-RABToBeModifiedItemBearerModReq.
	IdERABToBeModifiedItemBearerModReq int64 = 36

	// IdERABModifyItemBearerModRes is the integer constant for id-E-RABModifyItemBearerModRes.
	IdERABModifyItemBearerModRes int64 = 37

	// IdERABReleaseItem is the integer constant for id-E-RABReleaseItem.
	IdERABReleaseItem int64 = 38

	// IdERABSetupItemBearerSURes is the integer constant for id-E-RABSetupItemBearerSURes.
	IdERABSetupItemBearerSURes int64 = 39

	// IdSecurityContext is the integer constant for id-SecurityContext.
	IdSecurityContext int64 = 40

	// IdHandoverRestrictionList is the integer constant for id-HandoverRestrictionList.
	IdHandoverRestrictionList int64 = 41

	// IdUnknown42 is the integer constant for id-Unknown-42.
	IdUnknown42 int64 = 42

	// IdUEPagingID is the integer constant for id-UEPagingID.
	IdUEPagingID int64 = 43

	// IdPagingDRX is the integer constant for id-pagingDRX.
	IdPagingDRX int64 = 44

	// IdUnknown45 is the integer constant for id-Unknown-45.
	IdUnknown45 int64 = 45

	// IdTAIList is the integer constant for id-TAIList.
	IdTAIList int64 = 46

	// IdTAIItem is the integer constant for id-TAIItem.
	IdTAIItem int64 = 47

	// IdERABFailedToSetupListCtxtSURes is the integer constant for id-E-RABFailedToSetupListCtxtSURes.
	IdERABFailedToSetupListCtxtSURes int64 = 48

	// IdERABReleaseItemHOCmd is the integer constant for id-E-RABReleaseItemHOCmd.
	IdERABReleaseItemHOCmd int64 = 49

	// IdERABSetupItemCtxtSURes is the integer constant for id-E-RABSetupItemCtxtSURes.
	IdERABSetupItemCtxtSURes int64 = 50

	// IdERABSetupListCtxtSURes is the integer constant for id-E-RABSetupListCtxtSURes.
	IdERABSetupListCtxtSURes int64 = 51

	// IdERABToBeSetupItemCtxtSUReq is the integer constant for id-E-RABToBeSetupItemCtxtSUReq.
	IdERABToBeSetupItemCtxtSUReq int64 = 52

	// IdERABToBeSetupListHOReq is the integer constant for id-E-RABToBeSetupListHOReq.
	IdERABToBeSetupListHOReq int64 = 53

	// IdUnknown54 is the integer constant for id-Unknown-54.
	IdUnknown54 int64 = 54

	// IdGERANtoLTEHOInformationRes is the integer constant for id-GERANtoLTEHOInformationRes.
	IdGERANtoLTEHOInformationRes int64 = 55

	// IdUnknown56 is the integer constant for id-Unknown-56.
	IdUnknown56 int64 = 56

	// IdUTRANtoLTEHOInformationRes is the integer constant for id-UTRANtoLTEHOInformationRes.
	IdUTRANtoLTEHOInformationRes int64 = 57

	// IdCriticalityDiagnostics is the integer constant for id-CriticalityDiagnostics.
	IdCriticalityDiagnostics int64 = 58

	// IdGlobalENBID is the integer constant for id-Global-ENB-ID.
	IdGlobalENBID int64 = 59

	// IdENBname is the integer constant for id-eNBname.
	IdENBname int64 = 60

	// IdMMEname is the integer constant for id-MMEname.
	IdMMEname int64 = 61

	// IdUnknown62 is the integer constant for id-Unknown-62.
	IdUnknown62 int64 = 62

	// IdServedPLMNs is the integer constant for id-ServedPLMNs.
	IdServedPLMNs int64 = 63

	// IdSupportedTAs is the integer constant for id-SupportedTAs.
	IdSupportedTAs int64 = 64

	// IdTimeToWait is the integer constant for id-TimeToWait.
	IdTimeToWait int64 = 65

	// IdUEaggregateMaximumBitrate is the integer constant for id-uEaggregateMaximumBitrate.
	IdUEaggregateMaximumBitrate int64 = 66

	// IdTAI is the integer constant for id-TAI.
	IdTAI int64 = 67

	// IdUnknown68 is the integer constant for id-Unknown-68.
	IdUnknown68 int64 = 68

	// IdERABReleaseListBearerRelComp is the integer constant for id-E-RABReleaseListBearerRelComp.
	IdERABReleaseListBearerRelComp int64 = 69

	// IdCdma2000PDU is the integer constant for id-cdma2000PDU.
	IdCdma2000PDU int64 = 70

	// IdCdma2000RATType is the integer constant for id-cdma2000RATType.
	IdCdma2000RATType int64 = 71

	// IdCdma2000SectorID is the integer constant for id-cdma2000SectorID.
	IdCdma2000SectorID int64 = 72

	// IdSecurityKey is the integer constant for id-SecurityKey.
	IdSecurityKey int64 = 73

	// IdUERadioCapability is the integer constant for id-UERadioCapability.
	IdUERadioCapability int64 = 74

	// IdGUMMEIID is the integer constant for id-GUMMEI-ID.
	IdGUMMEIID int64 = 75

	// IdUnknown76 is the integer constant for id-Unknown-76.
	IdUnknown76 int64 = 76

	// IdUnknown77 is the integer constant for id-Unknown-77.
	IdUnknown77 int64 = 77

	// IdERABInformationListItem is the integer constant for id-E-RABInformationListItem.
	IdERABInformationListItem int64 = 78

	// IdDirectForwardingPathAvailability is the integer constant for id-Direct-Forwarding-Path-Availability.
	IdDirectForwardingPathAvailability int64 = 79

	// IdUEIdentityIndexValue is the integer constant for id-UEIdentityIndexValue.
	IdUEIdentityIndexValue int64 = 80

	// IdUnknown81 is the integer constant for id-Unknown-81.
	IdUnknown81 int64 = 81

	// IdUnknown82 is the integer constant for id-Unknown-82.
	IdUnknown82 int64 = 82

	// IdCdma2000HOStatus is the integer constant for id-cdma2000HOStatus.
	IdCdma2000HOStatus int64 = 83

	// IdCdma2000HORequiredIndication is the integer constant for id-cdma2000HORequiredIndication.
	IdCdma2000HORequiredIndication int64 = 84

	// IdUnknown85 is the integer constant for id-Unknown-85.
	IdUnknown85 int64 = 85

	// IdEUTRANTraceID is the integer constant for id-E-UTRAN-Trace-ID.
	IdEUTRANTraceID int64 = 86

	// IdRelativeMMECapacity is the integer constant for id-RelativeMMECapacity.
	IdRelativeMMECapacity int64 = 87

	// IdSourceMMEUES1APID is the integer constant for id-SourceMME-UE-S1AP-ID.
	IdSourceMMEUES1APID int64 = 88

	// IdBearersSubjectToStatusTransferItem is the integer constant for id-Bearers-SubjectToStatusTransfer-Item.
	IdBearersSubjectToStatusTransferItem int64 = 89

	// IdENBStatusTransferTransparentContainer is the integer constant for id-eNB-StatusTransfer-TransparentContainer.
	IdENBStatusTransferTransparentContainer int64 = 90

	// IdUEAssociatedLogicalS1ConnectionItem is the integer constant for id-UE-associatedLogicalS1-ConnectionItem.
	IdUEAssociatedLogicalS1ConnectionItem int64 = 91

	// IdResetType is the integer constant for id-ResetType.
	IdResetType int64 = 92

	// IdUEAssociatedLogicalS1ConnectionListResAck is the integer constant for id-UE-associatedLogicalS1-ConnectionListResAck.
	IdUEAssociatedLogicalS1ConnectionListResAck int64 = 93

	// IdERABToBeSwitchedULItem is the integer constant for id-E-RABToBeSwitchedULItem.
	IdERABToBeSwitchedULItem int64 = 94

	// IdERABToBeSwitchedULList is the integer constant for id-E-RABToBeSwitchedULList.
	IdERABToBeSwitchedULList int64 = 95

	// IdSTMSI is the integer constant for id-S-TMSI.
	IdSTMSI int64 = 96

	// IdCdma2000OneXRAND is the integer constant for id-cdma2000OneXRAND.
	IdCdma2000OneXRAND int64 = 97

	// IdRequestType is the integer constant for id-RequestType.
	IdRequestType int64 = 98

	// IdUES1APIDs is the integer constant for id-UE-S1AP-IDs.
	IdUES1APIDs int64 = 99

	// IdEUTRANCGI is the integer constant for id-EUTRAN-CGI.
	IdEUTRANCGI int64 = 100

	// IdOverloadResponse is the integer constant for id-OverloadResponse.
	IdOverloadResponse int64 = 101

	// IdCdma2000OneXSRVCCInfo is the integer constant for id-cdma2000OneXSRVCCInfo.
	IdCdma2000OneXSRVCCInfo int64 = 102

	// IdERABFailedToBeReleasedList is the integer constant for id-E-RABFailedToBeReleasedList.
	IdERABFailedToBeReleasedList int64 = 103

	// IdSourceToTargetTransparentContainer is the integer constant for id-Source-ToTarget-TransparentContainer.
	IdSourceToTargetTransparentContainer int64 = 104

	// IdServedGUMMEIs is the integer constant for id-ServedGUMMEIs.
	IdServedGUMMEIs int64 = 105

	// IdSubscriberProfileIDforRFP is the integer constant for id-SubscriberProfileIDforRFP.
	IdSubscriberProfileIDforRFP int64 = 106

	// IdUESecurityCapabilities is the integer constant for id-UESecurityCapabilities.
	IdUESecurityCapabilities int64 = 107

	// IdCSFallbackIndicator is the integer constant for id-CSFallbackIndicator.
	IdCSFallbackIndicator int64 = 108

	// IdCNDomain is the integer constant for id-CNDomain.
	IdCNDomain int64 = 109

	// IdERABReleasedList is the integer constant for id-E-RABReleasedList.
	IdERABReleasedList int64 = 110

	// IdMessageIdentifier is the integer constant for id-MessageIdentifier.
	IdMessageIdentifier int64 = 111

	// IdSerialNumber is the integer constant for id-SerialNumber.
	IdSerialNumber int64 = 112

	// IdWarningAreaList is the integer constant for id-WarningAreaList.
	IdWarningAreaList int64 = 113

	// IdRepetitionPeriod is the integer constant for id-RepetitionPeriod.
	IdRepetitionPeriod int64 = 114

	// IdNumberofBroadcastRequest is the integer constant for id-NumberofBroadcastRequest.
	IdNumberofBroadcastRequest int64 = 115

	// IdWarningType is the integer constant for id-WarningType.
	IdWarningType int64 = 116

	// IdWarningSecurityInfo is the integer constant for id-WarningSecurityInfo.
	IdWarningSecurityInfo int64 = 117

	// IdDataCodingScheme is the integer constant for id-DataCodingScheme.
	IdDataCodingScheme int64 = 118

	// IdWarningMessageContents is the integer constant for id-WarningMessageContents.
	IdWarningMessageContents int64 = 119

	// IdBroadcastCompletedAreaList is the integer constant for id-BroadcastCompletedAreaList.
	IdBroadcastCompletedAreaList int64 = 120

	// IdInterSystemInformationTransferTypeEDT is the integer constant for id-Inter-SystemInformationTransferTypeEDT.
	IdInterSystemInformationTransferTypeEDT int64 = 121

	// IdInterSystemInformationTransferTypeMDT is the integer constant for id-Inter-SystemInformationTransferTypeMDT.
	IdInterSystemInformationTransferTypeMDT int64 = 122

	// IdTargetToSourceTransparentContainer is the integer constant for id-Target-ToSource-TransparentContainer.
	IdTargetToSourceTransparentContainer int64 = 123

	// IdSRVCCOperationPossible is the integer constant for id-SRVCCOperationPossible.
	IdSRVCCOperationPossible int64 = 124

	// IdSRVCCHOIndication is the integer constant for id-SRVCCHOIndication.
	IdSRVCCHOIndication int64 = 125

	// IdNASDownlinkCount is the integer constant for id-NAS-DownlinkCount.
	IdNASDownlinkCount int64 = 126

	// IdCSGId is the integer constant for id-CSG-Id.
	IdCSGId int64 = 127

	// IdCSGIdList is the integer constant for id-CSG-IdList.
	IdCSGIdList int64 = 128

	// IdSONConfigurationTransferECT is the integer constant for id-SONConfigurationTransferECT.
	IdSONConfigurationTransferECT int64 = 129

	// IdSONConfigurationTransferMCT is the integer constant for id-SONConfigurationTransferMCT.
	IdSONConfigurationTransferMCT int64 = 130

	// IdTraceCollectionEntityIPAddress is the integer constant for id-TraceCollectionEntityIPAddress.
	IdTraceCollectionEntityIPAddress int64 = 131

	// IdMSClassmark2 is the integer constant for id-MSClassmark2.
	IdMSClassmark2 int64 = 132

	// IdMSClassmark3 is the integer constant for id-MSClassmark3.
	IdMSClassmark3 int64 = 133

	// IdRRCEstablishmentCause is the integer constant for id-RRC-Establishment-Cause.
	IdRRCEstablishmentCause int64 = 134

	// IdNASSecurityParametersfromEUTRAN is the integer constant for id-NASSecurityParametersfromE-UTRAN.
	IdNASSecurityParametersfromEUTRAN int64 = 135

	// IdNASSecurityParameterstoEUTRAN is the integer constant for id-NASSecurityParameterstoE-UTRAN.
	IdNASSecurityParameterstoEUTRAN int64 = 136

	// IdDefaultPagingDRX is the integer constant for id-DefaultPagingDRX.
	IdDefaultPagingDRX int64 = 137

	// IdSourceToTargetTransparentContainerSecondary is the integer constant for id-Source-ToTarget-TransparentContainer-Secondary.
	IdSourceToTargetTransparentContainerSecondary int64 = 138

	// IdTargetToSourceTransparentContainerSecondary is the integer constant for id-Target-ToSource-TransparentContainer-Secondary.
	IdTargetToSourceTransparentContainerSecondary int64 = 139

	// IdEUTRANRoundTripDelayEstimationInfo is the integer constant for id-EUTRANRoundTripDelayEstimationInfo.
	IdEUTRANRoundTripDelayEstimationInfo int64 = 140

	// IdBroadcastCancelledAreaList is the integer constant for id-BroadcastCancelledAreaList.
	IdBroadcastCancelledAreaList int64 = 141

	// IdConcurrentWarningMessageIndicator is the integer constant for id-ConcurrentWarningMessageIndicator.
	IdConcurrentWarningMessageIndicator int64 = 142

	// IdDataForwardingNotPossible is the integer constant for id-Data-Forwarding-Not-Possible.
	IdDataForwardingNotPossible int64 = 143

	// IdExtendedRepetitionPeriod is the integer constant for id-ExtendedRepetitionPeriod.
	IdExtendedRepetitionPeriod int64 = 144

	// IdCellAccessMode is the integer constant for id-CellAccessMode.
	IdCellAccessMode int64 = 145

	// IdCSGMembershipStatus is the integer constant for id-CSGMembershipStatus.
	IdCSGMembershipStatus int64 = 146

	// IdLPPaPDU is the integer constant for id-LPPa-PDU.
	IdLPPaPDU int64 = 147

	// IdRoutingID is the integer constant for id-Routing-ID.
	IdRoutingID int64 = 148

	// IdTimeSynchronisationInfo is the integer constant for id-Time-Synchronisation-Info.
	IdTimeSynchronisationInfo int64 = 149

	// IdPSServiceNotAvailable is the integer constant for id-PS-ServiceNotAvailable.
	IdPSServiceNotAvailable int64 = 150

	// IdPagingPriority is the integer constant for id-PagingPriority.
	IdPagingPriority int64 = 151

	// IdX2TNLConfigurationInfo is the integer constant for id-x2TNLConfigurationInfo.
	IdX2TNLConfigurationInfo int64 = 152

	// IdENBX2ExtendedTransportLayerAddresses is the integer constant for id-eNBX2ExtendedTransportLayerAddresses.
	IdENBX2ExtendedTransportLayerAddresses int64 = 153

	// IdGUMMEIList is the integer constant for id-GUMMEIList.
	IdGUMMEIList int64 = 154

	// IdGWTransportLayerAddress is the integer constant for id-GW-TransportLayerAddress.
	IdGWTransportLayerAddress int64 = 155

	// IdCorrelationID is the integer constant for id-Correlation-ID.
	IdCorrelationID int64 = 156

	// IdSourceMMEGUMMEI is the integer constant for id-SourceMME-GUMMEI.
	IdSourceMMEGUMMEI int64 = 157

	// IdMMEUES1APID2 is the integer constant for id-MME-UE-S1AP-ID-2.
	IdMMEUES1APID2 int64 = 158

	// IdRegisteredLAI is the integer constant for id-RegisteredLAI.
	IdRegisteredLAI int64 = 159

	// IdRelayNodeIndicator is the integer constant for id-RelayNode-Indicator.
	IdRelayNodeIndicator int64 = 160

	// IdTrafficLoadReductionIndication is the integer constant for id-TrafficLoadReductionIndication.
	IdTrafficLoadReductionIndication int64 = 161

	// IdMDTConfiguration is the integer constant for id-MDTConfiguration.
	IdMDTConfiguration int64 = 162

	// IdMMERelaySupportIndicator is the integer constant for id-MMERelaySupportIndicator.
	IdMMERelaySupportIndicator int64 = 163

	// IdGWContextReleaseIndication is the integer constant for id-GWContextReleaseIndication.
	IdGWContextReleaseIndication int64 = 164

	// IdManagementBasedMDTAllowed is the integer constant for id-ManagementBasedMDTAllowed.
	IdManagementBasedMDTAllowed int64 = 165

	// IdPrivacyIndicator is the integer constant for id-PrivacyIndicator.
	IdPrivacyIndicator int64 = 166

	// IdTimeUEStayedInCellEnhancedGranularity is the integer constant for id-Time-UE-StayedInCell-EnhancedGranularity.
	IdTimeUEStayedInCellEnhancedGranularity int64 = 167

	// IdHOCause is the integer constant for id-HO-Cause.
	IdHOCause int64 = 168

	// IdVoiceSupportMatchIndicator is the integer constant for id-VoiceSupportMatchIndicator.
	IdVoiceSupportMatchIndicator int64 = 169

	// IdGUMMEIType is the integer constant for id-GUMMEIType.
	IdGUMMEIType int64 = 170

	// IdM3Configuration is the integer constant for id-M3Configuration.
	IdM3Configuration int64 = 171

	// IdM4Configuration is the integer constant for id-M4Configuration.
	IdM4Configuration int64 = 172

	// IdM5Configuration is the integer constant for id-M5Configuration.
	IdM5Configuration int64 = 173

	// IdMDTLocationInfo is the integer constant for id-MDT-Location-Info.
	IdMDTLocationInfo int64 = 174

	// IdMobilityInformation is the integer constant for id-MobilityInformation.
	IdMobilityInformation int64 = 175

	// IdTunnelInformationForBBF is the integer constant for id-Tunnel-Information-for-BBF.
	IdTunnelInformationForBBF int64 = 176

	// IdManagementBasedMDTPLMNList is the integer constant for id-ManagementBasedMDTPLMNList.
	IdManagementBasedMDTPLMNList int64 = 177

	// IdSignallingBasedMDTPLMNList is the integer constant for id-SignallingBasedMDTPLMNList.
	IdSignallingBasedMDTPLMNList int64 = 178

	// IdULCOUNTValueExtended is the integer constant for id-ULCOUNTValueExtended.
	IdULCOUNTValueExtended int64 = 179

	// IdDLCOUNTValueExtended is the integer constant for id-DLCOUNTValueExtended.
	IdDLCOUNTValueExtended int64 = 180

	// IdReceiveStatusOfULPDCPSDUsExtended is the integer constant for id-ReceiveStatusOfULPDCPSDUsExtended.
	IdReceiveStatusOfULPDCPSDUsExtended int64 = 181

	// IdECGIListForRestart is the integer constant for id-ECGIListForRestart.
	IdECGIListForRestart int64 = 182

	// IdSIPTOCorrelationID is the integer constant for id-SIPTO-Correlation-ID.
	IdSIPTOCorrelationID int64 = 183

	// IdSIPTOLGWTransportLayerAddress is the integer constant for id-SIPTO-L-GW-TransportLayerAddress.
	IdSIPTOLGWTransportLayerAddress int64 = 184

	// IdTransportInformation is the integer constant for id-TransportInformation.
	IdTransportInformation int64 = 185

	// IdLHNID is the integer constant for id-LHN-ID.
	IdLHNID int64 = 186

	// IdAdditionalCSFallbackIndicator is the integer constant for id-AdditionalCSFallbackIndicator.
	IdAdditionalCSFallbackIndicator int64 = 187

	// IdTAIListForRestart is the integer constant for id-TAIListForRestart.
	IdTAIListForRestart int64 = 188

	// IdUserLocationInformation is the integer constant for id-UserLocationInformation.
	IdUserLocationInformation int64 = 189

	// IdEmergencyAreaIDListForRestart is the integer constant for id-EmergencyAreaIDListForRestart.
	IdEmergencyAreaIDListForRestart int64 = 190

	// IdKillAllWarningMessages is the integer constant for id-KillAllWarningMessages.
	IdKillAllWarningMessages int64 = 191

	// IdMaskedIMEISV is the integer constant for id-Masked-IMEISV.
	IdMaskedIMEISV int64 = 192

	// IdENBIndirectX2TransportLayerAddresses is the integer constant for id-eNBIndirectX2TransportLayerAddresses.
	IdENBIndirectX2TransportLayerAddresses int64 = 193

	// IdUEHistoryInformationFromTheUE is the integer constant for id-uE-HistoryInformationFromTheUE.
	IdUEHistoryInformationFromTheUE int64 = 194

	// IdProSeAuthorized is the integer constant for id-ProSeAuthorized.
	IdProSeAuthorized int64 = 195

	// IdExpectedUEBehaviour is the integer constant for id-ExpectedUEBehaviour.
	IdExpectedUEBehaviour int64 = 196

	// IdLoggedMBSFNMDT is the integer constant for id-LoggedMBSFNMDT.
	IdLoggedMBSFNMDT int64 = 197

	// IdUERadioCapabilityForPaging is the integer constant for id-UERadioCapabilityForPaging.
	IdUERadioCapabilityForPaging int64 = 198

	// IdERABToBeModifiedListBearerModInd is the integer constant for id-E-RABToBeModifiedListBearerModInd.
	IdERABToBeModifiedListBearerModInd int64 = 199

	// IdERABToBeModifiedItemBearerModInd is the integer constant for id-E-RABToBeModifiedItemBearerModInd.
	IdERABToBeModifiedItemBearerModInd int64 = 200

	// IdERABNotToBeModifiedListBearerModInd is the integer constant for id-E-RABNotToBeModifiedListBearerModInd.
	IdERABNotToBeModifiedListBearerModInd int64 = 201

	// IdERABNotToBeModifiedItemBearerModInd is the integer constant for id-E-RABNotToBeModifiedItemBearerModInd.
	IdERABNotToBeModifiedItemBearerModInd int64 = 202

	// IdERABModifyListBearerModConf is the integer constant for id-E-RABModifyListBearerModConf.
	IdERABModifyListBearerModConf int64 = 203

	// IdERABModifyItemBearerModConf is the integer constant for id-E-RABModifyItemBearerModConf.
	IdERABModifyItemBearerModConf int64 = 204

	// IdERABFailedToModifyListBearerModConf is the integer constant for id-E-RABFailedToModifyListBearerModConf.
	IdERABFailedToModifyListBearerModConf int64 = 205

	// IdSONInformationReport is the integer constant for id-SON-Information-Report.
	IdSONInformationReport int64 = 206

	// IdMutingAvailabilityIndication is the integer constant for id-Muting-Availability-Indication.
	IdMutingAvailabilityIndication int64 = 207

	// IdMutingPatternInformation is the integer constant for id-Muting-Pattern-Information.
	IdMutingPatternInformation int64 = 208

	// IdSynchronisationInformation is the integer constant for id-Synchronisation-Information.
	IdSynchronisationInformation int64 = 209

	// IdERABToBeReleasedListBearerModConf is the integer constant for id-E-RABToBeReleasedListBearerModConf.
	IdERABToBeReleasedListBearerModConf int64 = 210

	// IdAssistanceDataForPaging is the integer constant for id-AssistanceDataForPaging.
	IdAssistanceDataForPaging int64 = 211

	// IdCellIdentifierAndCELevelForCECapableUEs is the integer constant for id-CellIdentifierAndCELevelForCECapableUEs.
	IdCellIdentifierAndCELevelForCECapableUEs int64 = 212

	// IdInformationOnRecommendedCellsAndENBsForPaging is the integer constant for id-InformationOnRecommendedCellsAndENBsForPaging.
	IdInformationOnRecommendedCellsAndENBsForPaging int64 = 213

	// IdRecommendedCellItem is the integer constant for id-RecommendedCellItem.
	IdRecommendedCellItem int64 = 214

	// IdRecommendedENBItem is the integer constant for id-RecommendedENBItem.
	IdRecommendedENBItem int64 = 215

	// IdProSeUEtoNetworkRelaying is the integer constant for id-ProSeUEtoNetworkRelaying.
	IdProSeUEtoNetworkRelaying int64 = 216

	// IdULCOUNTValuePDCPSNlength18 is the integer constant for id-ULCOUNTValuePDCP-SNlength18.
	IdULCOUNTValuePDCPSNlength18 int64 = 217

	// IdDLCOUNTValuePDCPSNlength18 is the integer constant for id-DLCOUNTValuePDCP-SNlength18.
	IdDLCOUNTValuePDCPSNlength18 int64 = 218

	// IdReceiveStatusOfULPDCPSDUsPDCPSNlength18 is the integer constant for id-ReceiveStatusOfULPDCPSDUsPDCP-SNlength18.
	IdReceiveStatusOfULPDCPSDUsPDCPSNlength18 int64 = 219

	// IdM6Configuration is the integer constant for id-M6Configuration.
	IdM6Configuration int64 = 220

	// IdM7Configuration is the integer constant for id-M7Configuration.
	IdM7Configuration int64 = 221

	// IdPWSfailedECGIList is the integer constant for id-PWSfailedECGIList.
	IdPWSfailedECGIList int64 = 222

	// IdMMEGroupID is the integer constant for id-MME-Group-ID.
	IdMMEGroupID int64 = 223

	// IdAdditionalGUTI is the integer constant for id-Additional-GUTI.
	IdAdditionalGUTI int64 = 224

	// IdS1Message is the integer constant for id-S1-Message.
	IdS1Message int64 = 225

	// IdCSGMembershipInfo is the integer constant for id-CSGMembershipInfo.
	IdCSGMembershipInfo int64 = 226

	// IdPagingEDRXInformation is the integer constant for id-Paging-eDRXInformation.
	IdPagingEDRXInformation int64 = 227

	// IdUERetentionInformation is the integer constant for id-UE-RetentionInformation.
	IdUERetentionInformation int64 = 228

	// IdUnknown229 is the integer constant for id-Unknown-229.
	IdUnknown229 int64 = 229

	// IdUEUsageType is the integer constant for id-UE-Usage-Type.
	IdUEUsageType int64 = 230

	// IdExtendedUEIdentityIndexValue is the integer constant for id-extended-UEIdentityIndexValue.
	IdExtendedUEIdentityIndexValue int64 = 231

	// IdRATType is the integer constant for id-RAT-Type.
	IdRATType int64 = 232

	// IdBearerType is the integer constant for id-BearerType.
	IdBearerType int64 = 233

	// IdNBIoTDefaultPagingDRX is the integer constant for id-NB-IoT-DefaultPagingDRX.
	IdNBIoTDefaultPagingDRX int64 = 234

	// IdERABFailedToResumeListResumeReq is the integer constant for id-E-RABFailedToResumeListResumeReq.
	IdERABFailedToResumeListResumeReq int64 = 235

	// IdERABFailedToResumeItemResumeReq is the integer constant for id-E-RABFailedToResumeItemResumeReq.
	IdERABFailedToResumeItemResumeReq int64 = 236

	// IdERABFailedToResumeListResumeRes is the integer constant for id-E-RABFailedToResumeListResumeRes.
	IdERABFailedToResumeListResumeRes int64 = 237

	// IdERABFailedToResumeItemResumeRes is the integer constant for id-E-RABFailedToResumeItemResumeRes.
	IdERABFailedToResumeItemResumeRes int64 = 238

	// IdNBIoTPagingEDRXInformation is the integer constant for id-NB-IoT-Paging-eDRXInformation.
	IdNBIoTPagingEDRXInformation int64 = 239

	// IdV2XServicesAuthorized is the integer constant for id-V2XServicesAuthorized.
	IdV2XServicesAuthorized int64 = 240

	// IdUEUserPlaneCIoTSupportIndicator is the integer constant for id-UEUserPlaneCIoTSupportIndicator.
	IdUEUserPlaneCIoTSupportIndicator int64 = 241

	// IdCEModeBSupportIndicator is the integer constant for id-CE-mode-B-SupportIndicator.
	IdCEModeBSupportIndicator int64 = 242

	// IdSRVCCOperationNotPossible is the integer constant for id-SRVCCOperationNotPossible.
	IdSRVCCOperationNotPossible int64 = 243

	// IdNBIoTUEIdentityIndexValue is the integer constant for id-NB-IoT-UEIdentityIndexValue.
	IdNBIoTUEIdentityIndexValue int64 = 244

	// IdRRCResumeCause is the integer constant for id-RRC-Resume-Cause.
	IdRRCResumeCause int64 = 245

	// IdDCNID is the integer constant for id-DCN-ID.
	IdDCNID int64 = 246

	// IdServedDCNs is the integer constant for id-ServedDCNs.
	IdServedDCNs int64 = 247

	// IdUESidelinkAggregateMaximumBitrate is the integer constant for id-UESidelinkAggregateMaximumBitrate.
	IdUESidelinkAggregateMaximumBitrate int64 = 248

	// IdDLNASPDUDeliveryAckRequest is the integer constant for id-DLNASPDUDeliveryAckRequest.
	IdDLNASPDUDeliveryAckRequest int64 = 249

	// IdCoverageLevel is the integer constant for id-Coverage-Level.
	IdCoverageLevel int64 = 250

	// IdEnhancedCoverageRestricted is the integer constant for id-EnhancedCoverageRestricted.
	IdEnhancedCoverageRestricted int64 = 251

	// IdUELevelQoSParameters is the integer constant for id-UE-Level-QoS-Parameters.
	IdUELevelQoSParameters int64 = 252

	// IdDLCPSecurityInformation is the integer constant for id-DL-CP-SecurityInformation.
	IdDLCPSecurityInformation int64 = 253

	// IdULCPSecurityInformation is the integer constant for id-UL-CP-SecurityInformation.
	IdULCPSecurityInformation int64 = 254

	// IdExtendedERABMaximumBitrateDL is the integer constant for id-extended-e-RAB-MaximumBitrateDL.
	IdExtendedERABMaximumBitrateDL int64 = 255

	// IdExtendedERABMaximumBitrateUL is the integer constant for id-extended-e-RAB-MaximumBitrateUL.
	IdExtendedERABMaximumBitrateUL int64 = 256

	// IdExtendedERABGuaranteedBitrateDL is the integer constant for id-extended-e-RAB-GuaranteedBitrateDL.
	IdExtendedERABGuaranteedBitrateDL int64 = 257

	// IdExtendedERABGuaranteedBitrateUL is the integer constant for id-extended-e-RAB-GuaranteedBitrateUL.
	IdExtendedERABGuaranteedBitrateUL int64 = 258

	// IdExtendedUEaggregateMaximumBitRateDL is the integer constant for id-extended-uEaggregateMaximumBitRateDL.
	IdExtendedUEaggregateMaximumBitRateDL int64 = 259

	// IdExtendedUEaggregateMaximumBitRateUL is the integer constant for id-extended-uEaggregateMaximumBitRateUL.
	IdExtendedUEaggregateMaximumBitRateUL int64 = 260

	// IdNRrestrictioninEPSasSecondaryRAT is the integer constant for id-NRrestrictioninEPSasSecondaryRAT.
	IdNRrestrictioninEPSasSecondaryRAT int64 = 261

	// IdUEAppLayerMeasConfig is the integer constant for id-UEAppLayerMeasConfig.
	IdUEAppLayerMeasConfig int64 = 262

	// IdUEApplicationLayerMeasurementCapability is the integer constant for id-UE-Application-Layer-Measurement-Capability.
	IdUEApplicationLayerMeasurementCapability int64 = 263

	// IdSecondaryRATDataUsageReportList is the integer constant for id-SecondaryRATDataUsageReportList.
	IdSecondaryRATDataUsageReportList int64 = 264

	// IdSecondaryRATDataUsageReportItem is the integer constant for id-SecondaryRATDataUsageReportItem.
	IdSecondaryRATDataUsageReportItem int64 = 265

	// IdHandoverFlag is the integer constant for id-HandoverFlag.
	IdHandoverFlag int64 = 266

	// IdERABUsageReportItem is the integer constant for id-E-RABUsageReportItem.
	IdERABUsageReportItem int64 = 267

	// IdSecondaryRATDataUsageRequest is the integer constant for id-SecondaryRATDataUsageRequest.
	IdSecondaryRATDataUsageRequest int64 = 268

	// IdNRUESecurityCapabilities is the integer constant for id-NRUESecurityCapabilities.
	IdNRUESecurityCapabilities int64 = 269

	// IdUnlicensedSpectrumRestriction is the integer constant for id-UnlicensedSpectrumRestriction.
	IdUnlicensedSpectrumRestriction int64 = 270

	// IdCEModeBRestricted is the integer constant for id-CE-ModeBRestricted.
	IdCEModeBRestricted int64 = 271

	// IdLTEMIndication is the integer constant for id-LTE-M-Indication.
	IdLTEMIndication int64 = 272

	// IdDownlinkPacketLossRate is the integer constant for id-DownlinkPacketLossRate.
	IdDownlinkPacketLossRate int64 = 273

	// IdUplinkPacketLossRate is the integer constant for id-UplinkPacketLossRate.
	IdUplinkPacketLossRate int64 = 274

	// IdUECapabilityInfoRequest is the integer constant for id-UECapabilityInfoRequest.
	IdUECapabilityInfoRequest int64 = 275

	// IdServiceType is the integer constant for id-serviceType.
	IdServiceType int64 = 276

	// IdAerialUEsubscriptionInformation is the integer constant for id-AerialUEsubscriptionInformation.
	IdAerialUEsubscriptionInformation int64 = 277

	// IdSubscriptionBasedUEDifferentiationInfo is the integer constant for id-Subscription-Based-UE-DifferentiationInfo.
	IdSubscriptionBasedUEDifferentiationInfo int64 = 278

	// IdUnknown279 is the integer constant for id-Unknown-279.
	IdUnknown279 int64 = 279

	// IdEndIndication is the integer constant for id-EndIndication.
	IdEndIndication int64 = 280

	// IdEDTSession is the integer constant for id-EDT-Session.
	IdEDTSession int64 = 281

	// IdCNTypeRestrictions is the integer constant for id-CNTypeRestrictions.
	IdCNTypeRestrictions int64 = 282

	// IdPendingDataIndication is the integer constant for id-PendingDataIndication.
	IdPendingDataIndication int64 = 283

	// IdBluetoothMeasurementConfiguration is the integer constant for id-BluetoothMeasurementConfiguration.
	IdBluetoothMeasurementConfiguration int64 = 284

	// IdWLANMeasurementConfiguration is the integer constant for id-WLANMeasurementConfiguration.
	IdWLANMeasurementConfiguration int64 = 285

	// IdWarningAreaCoordinates is the integer constant for id-WarningAreaCoordinates.
	IdWarningAreaCoordinates int64 = 286

	// IdNRrestrictionin5GS is the integer constant for id-NRrestrictionin5GS.
	IdNRrestrictionin5GS int64 = 287

	// IdPSCellInformation is the integer constant for id-PSCellInformation.
	IdPSCellInformation int64 = 288

	// IdUnknown289 is the integer constant for id-Unknown-289.
	IdUnknown289 int64 = 289

	// IdLastNGRANPLMNIdentity is the integer constant for id-LastNG-RANPLMNIdentity.
	IdLastNGRANPLMNIdentity int64 = 290

	// IdConnectedengNBList is the integer constant for id-ConnectedengNBList.
	IdConnectedengNBList int64 = 291

	// IdConnectedengNBToAddList is the integer constant for id-ConnectedengNBToAddList.
	IdConnectedengNBToAddList int64 = 292

	// IdConnectedengNBToRemoveList is the integer constant for id-ConnectedengNBToRemoveList.
	IdConnectedengNBToRemoveList int64 = 293

	// IdENDCSONConfigurationTransferECT is the integer constant for id-EN-DCSONConfigurationTransfer-ECT.
	IdENDCSONConfigurationTransferECT int64 = 294

	// IdENDCSONConfigurationTransferMCT is the integer constant for id-EN-DCSONConfigurationTransfer-MCT.
	IdENDCSONConfigurationTransferMCT int64 = 295

	// IdIMSvoiceEPSfallbackfrom5G is the integer constant for id-IMSvoiceEPSfallbackfrom5G.
	IdIMSvoiceEPSfallbackfrom5G int64 = 296

	// IdTimeSinceSecondaryNodeRelease is the integer constant for id-TimeSinceSecondaryNodeRelease.
	IdTimeSinceSecondaryNodeRelease int64 = 297

	// IdRequestTypeAdditionalInfo is the integer constant for id-RequestTypeAdditionalInfo.
	IdRequestTypeAdditionalInfo int64 = 298

	// IdAdditionalRRMPriorityIndex is the integer constant for id-AdditionalRRMPriorityIndex.
	IdAdditionalRRMPriorityIndex int64 = 299

	// IdContextatSource is the integer constant for id-ContextatSource.
	IdContextatSource int64 = 300

	// IdIABAuthorized is the integer constant for id-IAB-Authorized.
	IdIABAuthorized int64 = 301

	// IdIABNodeIndication is the integer constant for id-IAB-Node-Indication.
	IdIABNodeIndication int64 = 302

	// IdIABSupported is the integer constant for id-IAB-Supported.
	IdIABSupported int64 = 303

	// IdDataSize is the integer constant for id-DataSize.
	IdDataSize int64 = 304

	// IdEthernetType is the integer constant for id-Ethernet-Type.
	IdEthernetType int64 = 305

	// IdNRV2XServicesAuthorized is the integer constant for id-NRV2XServicesAuthorized.
	IdNRV2XServicesAuthorized int64 = 306

	// IdNRUESidelinkAggregateMaximumBitrate is the integer constant for id-NRUESidelinkAggregateMaximumBitrate.
	IdNRUESidelinkAggregateMaximumBitrate int64 = 307

	// IdPC5QoSParameters is the integer constant for id-PC5QoSParameters.
	IdPC5QoSParameters int64 = 308

	// IdIntersystemSONConfigurationTransferMCT is the integer constant for id-IntersystemSONConfigurationTransferMCT.
	IdIntersystemSONConfigurationTransferMCT int64 = 309

	// IdIntersystemSONConfigurationTransferECT is the integer constant for id-IntersystemSONConfigurationTransferECT.
	IdIntersystemSONConfigurationTransferECT int64 = 310

	// IdIntersystemMeasurementConfiguration is the integer constant for id-IntersystemMeasurementConfiguration.
	IdIntersystemMeasurementConfiguration int64 = 311

	// IdSourceNodeID is the integer constant for id-SourceNodeID.
	IdSourceNodeID int64 = 312

	// IdNBIoTRLFReportContainer is the integer constant for id-NB-IoT-RLF-Report-Container.
	IdNBIoTRLFReportContainer int64 = 313

	// IdUERadioCapabilityID is the integer constant for id-UERadioCapabilityID.
	IdUERadioCapabilityID int64 = 314

	// IdUERadioCapabilityNRFormat is the integer constant for id-UERadioCapability-NR-Format.
	IdUERadioCapabilityNRFormat int64 = 315

	// IdMDTConfigurationNR is the integer constant for id-MDTConfigurationNR.
	IdMDTConfigurationNR int64 = 316

	// IdDAPSRequestInfo is the integer constant for id-DAPSRequestInfo.
	IdDAPSRequestInfo int64 = 317

	// IdDAPSResponseInfoList is the integer constant for id-DAPSResponseInfoList.
	IdDAPSResponseInfoList int64 = 318

	// IdDAPSResponseInfoItem is the integer constant for id-DAPSResponseInfoItem.
	IdDAPSResponseInfoItem int64 = 319

	// IdNotifySourceeNB is the integer constant for id-NotifySourceeNB.
	IdNotifySourceeNB int64 = 320

	// IdENBEarlyStatusTransferTransparentContainer is the integer constant for id-eNB-EarlyStatusTransfer-TransparentContainer.
	IdENBEarlyStatusTransferTransparentContainer int64 = 321

	// IdBearersSubjectToEarlyStatusTransferItem is the integer constant for id-Bearers-SubjectToEarlyStatusTransfer-Item.
	IdBearersSubjectToEarlyStatusTransferItem int64 = 322

	// IdWUSAssistanceInformation is the integer constant for id-WUS-Assistance-Information.
	IdWUSAssistanceInformation int64 = 323

	// IdNBIoTPagingDRX is the integer constant for id-NB-IoT-PagingDRX.
	IdNBIoTPagingDRX int64 = 324

	// IdTraceCollectionEntityURI is the integer constant for id-TraceCollectionEntityURI.
	IdTraceCollectionEntityURI int64 = 325

	// IdEmergencyIndicator is the integer constant for id-EmergencyIndicator.
	IdEmergencyIndicator int64 = 326

	// IdUERadioCapabilityForPagingNRFormat is the integer constant for id-UERadioCapabilityForPaging-NR-Format.
	IdUERadioCapabilityForPagingNRFormat int64 = 327

	// IdSourceTransportLayerAddress is the integer constant for id-SourceTransportLayerAddress.
	IdSourceTransportLayerAddress int64 = 328

	// IdLastVisitedPSCellList is the integer constant for id-lastVisitedPSCellList.
	IdLastVisitedPSCellList int64 = 329

	// IdRACSIndication is the integer constant for id-RACSIndication.
	IdRACSIndication int64 = 330

	// IdPagingCause is the integer constant for id-PagingCause.
	IdPagingCause int64 = 331

	// IdSecurityIndication is the integer constant for id-SecurityIndication.
	IdSecurityIndication int64 = 332

	// IdSecurityResult is the integer constant for id-SecurityResult.
	IdSecurityResult int64 = 333

	// IdERABSecurityResultItem is the integer constant for id-E-RABSecurityResultItem.
	IdERABSecurityResultItem int64 = 334

	// IdERABSecurityResultList is the integer constant for id-E-RABSecurityResultList.
	IdERABSecurityResultList int64 = 335

	// IdRATRestrictions is the integer constant for id-RAT-Restrictions.
	IdRATRestrictions int64 = 336

	// IdUEContextReferenceatSourceeNB is the integer constant for id-UEContextReferenceatSourceeNB.
	IdUEContextReferenceatSourceeNB int64 = 337

	// IdUnknown338 is the integer constant for id-Unknown-338.
	IdUnknown338 int64 = 338

	// IdLTENTNTAIInformation is the integer constant for id-LTE-NTN-TAI-Information.
	IdLTENTNTAIInformation int64 = 339

	// IdSourceNodeTransportLayerAddress is the integer constant for id-SourceNodeTransportLayerAddress.
	IdSourceNodeTransportLayerAddress int64 = 340

	// IdERABToBeUpdatedList is the integer constant for id-E-RABToBeUpdatedList.
	IdERABToBeUpdatedList int64 = 341

	// IdERABToBeUpdatedItem is the integer constant for id-E-RABToBeUpdatedItem.
	IdERABToBeUpdatedItem int64 = 342

	// IdSourceSNID is the integer constant for id-SourceSNID.
	IdSourceSNID int64 = 343

	// IdLoggedMDTTrigger is the integer constant for id-LoggedMDTTrigger.
	IdLoggedMDTTrigger int64 = 344

	// IdSensorMeasurementConfiguration is the integer constant for id-SensorMeasurementConfiguration.
	IdSensorMeasurementConfiguration int64 = 345

	// IdM4ReportAmount is the integer constant for id-M4ReportAmount.
	IdM4ReportAmount int64 = 346

	// IdM5ReportAmount is the integer constant for id-M5ReportAmount.
	IdM5ReportAmount int64 = 347

	// IdM6ReportAmount is the integer constant for id-M6ReportAmount.
	IdM6ReportAmount int64 = 348

	// IdM7ReportAmount is the integer constant for id-M7ReportAmount.
	IdM7ReportAmount int64 = 349

	// IdTimeBasedHandoverInformation is the integer constant for id-TimeBasedHandoverInformation.
	IdTimeBasedHandoverInformation int64 = 350

	// IdBearersSubjectToDLDiscardingItem is the integer constant for id-Bearers-SubjectToDLDiscarding-Item.
	IdBearersSubjectToDLDiscardingItem int64 = 351

	// IdBearersSubjectToDLDiscardingList is the integer constant for id-Bearers-SubjectToDLDiscardingList.
	IdBearersSubjectToDLDiscardingList int64 = 352

	// IdCoarseUELocationRequested is the integer constant for id-CoarseUELocationRequested.
	IdCoarseUELocationRequested int64 = 353

	// IdCoarseUELocation is the integer constant for id-CoarseUELocation.
	IdCoarseUELocation int64 = 354

	// IdTimeRefDistribution is the integer constant for id-TimeRefDistribution.
	IdTimeRefDistribution int64 = 355

	// IdRequestedTNLInfo is the integer constant for id-RequestedTNLInfo.
	IdRequestedTNLInfo int64 = 356
)
