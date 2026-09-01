// Code generated from ASN.1 module "X2AP-Constants". DO NOT EDIT.

package x2ap

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

	// IdHandoverCancel is the integer constant for IdHandoverCancel.
	IdHandoverCancel int64 = 1

	// IdLoadIndication is the integer constant for IdLoadIndication.
	IdLoadIndication int64 = 2

	// IdErrorIndication is the integer constant for IdErrorIndication.
	IdErrorIndication int64 = 3

	// IdSnStatusTransfer is the integer constant for IdSnStatusTransfer.
	IdSnStatusTransfer int64 = 4

	// IdUEContextRelease is the integer constant for IdUEContextRelease.
	IdUEContextRelease int64 = 5

	// IdX2Setup is the integer constant for IdX2Setup.
	IdX2Setup int64 = 6

	// IdReset is the integer constant for IdReset.
	IdReset int64 = 7

	// IdENBConfigurationUpdate is the integer constant for IdENBConfigurationUpdate.
	IdENBConfigurationUpdate int64 = 8

	// IdResourceStatusReportingInitiation is the integer constant for IdResourceStatusReportingInitiation.
	IdResourceStatusReportingInitiation int64 = 9

	// IdResourceStatusReporting is the integer constant for IdResourceStatusReporting.
	IdResourceStatusReporting int64 = 10

	// IdPrivateMessage is the integer constant for IdPrivateMessage.
	IdPrivateMessage int64 = 11

	// IdMobilitySettingsChange is the integer constant for IdMobilitySettingsChange.
	IdMobilitySettingsChange int64 = 12

	// IdRLFIndication is the integer constant for IdRLFIndication.
	IdRLFIndication int64 = 13

	// IdHandoverReport is the integer constant for IdHandoverReport.
	IdHandoverReport int64 = 14

	// IdCellActivation is the integer constant for IdCellActivation.
	IdCellActivation int64 = 15

	// IdX2Release is the integer constant for IdX2Release.
	IdX2Release int64 = 16

	// IdX2APMessageTransfer is the integer constant for IdX2APMessageTransfer.
	IdX2APMessageTransfer int64 = 17

	// IdX2Removal is the integer constant for IdX2Removal.
	IdX2Removal int64 = 18

	// IdSeNBAdditionPreparation is the integer constant for IdSeNBAdditionPreparation.
	IdSeNBAdditionPreparation int64 = 19

	// IdSeNBReconfigurationCompletion is the integer constant for IdSeNBReconfigurationCompletion.
	IdSeNBReconfigurationCompletion int64 = 20

	// IdMeNBinitiatedSeNBModificationPreparation is the integer constant for IdMeNBinitiatedSeNBModificationPreparation.
	IdMeNBinitiatedSeNBModificationPreparation int64 = 21

	// IdSeNBinitiatedSeNBModification is the integer constant for IdSeNBinitiatedSeNBModification.
	IdSeNBinitiatedSeNBModification int64 = 22

	// IdMeNBinitiatedSeNBRelease is the integer constant for IdMeNBinitiatedSeNBRelease.
	IdMeNBinitiatedSeNBRelease int64 = 23

	// IdSeNBinitiatedSeNBRelease is the integer constant for IdSeNBinitiatedSeNBRelease.
	IdSeNBinitiatedSeNBRelease int64 = 24

	// IdSeNBCounterCheck is the integer constant for IdSeNBCounterCheck.
	IdSeNBCounterCheck int64 = 25

	// IdRetrieveUEContext is the integer constant for IdRetrieveUEContext.
	IdRetrieveUEContext int64 = 26

	// IdSgNBAdditionPreparation is the integer constant for IdSgNBAdditionPreparation.
	IdSgNBAdditionPreparation int64 = 27

	// IdSgNBReconfigurationCompletion is the integer constant for IdSgNBReconfigurationCompletion.
	IdSgNBReconfigurationCompletion int64 = 28

	// IdMeNBinitiatedSgNBModificationPreparation is the integer constant for IdMeNBinitiatedSgNBModificationPreparation.
	IdMeNBinitiatedSgNBModificationPreparation int64 = 29

	// IdSgNBinitiatedSgNBModification is the integer constant for IdSgNBinitiatedSgNBModification.
	IdSgNBinitiatedSgNBModification int64 = 30

	// IdMeNBinitiatedSgNBRelease is the integer constant for IdMeNBinitiatedSgNBRelease.
	IdMeNBinitiatedSgNBRelease int64 = 31

	// IdSgNBinitiatedSgNBRelease is the integer constant for IdSgNBinitiatedSgNBRelease.
	IdSgNBinitiatedSgNBRelease int64 = 32

	// IdSgNBCounterCheck is the integer constant for IdSgNBCounterCheck.
	IdSgNBCounterCheck int64 = 33

	// IdSgNBChange is the integer constant for IdSgNBChange.
	IdSgNBChange int64 = 34

	// IdRRCTransfer is the integer constant for IdRRCTransfer.
	IdRRCTransfer int64 = 35

	// IdEndcX2Setup is the integer constant for IdEndcX2Setup.
	IdEndcX2Setup int64 = 36

	// IdEndcConfigurationUpdate is the integer constant for IdEndcConfigurationUpdate.
	IdEndcConfigurationUpdate int64 = 37

	// IdSecondaryRATDataUsageReport is the integer constant for IdSecondaryRATDataUsageReport.
	IdSecondaryRATDataUsageReport int64 = 38

	// IdEndcCellActivation is the integer constant for IdEndcCellActivation.
	IdEndcCellActivation int64 = 39

	// IdEndcPartialReset is the integer constant for IdEndcPartialReset.
	IdEndcPartialReset int64 = 40

	// IdEUTRANRCellResourceCoordination is the integer constant for IdEUTRANRCellResourceCoordination.
	IdEUTRANRCellResourceCoordination int64 = 41

	// IdSgNBActivityNotification is the integer constant for IdSgNBActivityNotification.
	IdSgNBActivityNotification int64 = 42

	// IdEndcX2Removal is the integer constant for IdEndcX2Removal.
	IdEndcX2Removal int64 = 43

	// IdDataForwardingAddressIndication is the integer constant for IdDataForwardingAddressIndication.
	IdDataForwardingAddressIndication int64 = 44

	// IdGNBStatusIndication is the integer constant for IdGNBStatusIndication.
	IdGNBStatusIndication int64 = 45

	// IdDeactivateTrace is the integer constant for IdDeactivateTrace.
	IdDeactivateTrace int64 = 46

	// IdTraceStart is the integer constant for IdTraceStart.
	IdTraceStart int64 = 47

	// IdEndcConfigurationTransfer is the integer constant for IdEndcConfigurationTransfer.
	IdEndcConfigurationTransfer int64 = 48

	// IdHandoverSuccess is the integer constant for IdHandoverSuccess.
	IdHandoverSuccess int64 = 49

	// IdConditionalHandoverCancel is the integer constant for IdConditionalHandoverCancel.
	IdConditionalHandoverCancel int64 = 50

	// IdEarlyStatusTransfer is the integer constant for IdEarlyStatusTransfer.
	IdEarlyStatusTransfer int64 = 51

	// IdCellTrafficTrace is the integer constant for IdCellTrafficTrace.
	IdCellTrafficTrace int64 = 52

	// IdEndcresourceStatusReporting is the integer constant for IdEndcresourceStatusReporting.
	IdEndcresourceStatusReporting int64 = 53

	// IdEndcresourceStatusReportingInitiation is the integer constant for IdEndcresourceStatusReportingInitiation.
	IdEndcresourceStatusReportingInitiation int64 = 54

	// IdF1CTrafficTransfer is the integer constant for IdF1CTrafficTransfer.
	IdF1CTrafficTransfer int64 = 55

	// IdUERadioCapabilityIDMapping is the integer constant for IdUERadioCapabilityIDMapping.
	IdUERadioCapabilityIDMapping int64 = 56

	// IdAccessAndMobilityIndication is the integer constant for IdAccessAndMobilityIndication.
	IdAccessAndMobilityIndication int64 = 57

	// IdProcedureCode58NotToBeUsed is the integer constant for IdProcedureCode58NotToBeUsed.
	IdProcedureCode58NotToBeUsed int64 = 58

	// IdCPCCancel is the integer constant for IdCPCCancel.
	IdCPCCancel int64 = 59

	// IdRachIndication is the integer constant for IdRachIndication.
	IdRachIndication int64 = 60

	// IdScgFailureInformationReport is the integer constant for IdScgFailureInformationReport.
	IdScgFailureInformationReport int64 = 61

	// IdScgFailureTransfer is the integer constant for IdScgFailureTransfer.
	IdScgFailureTransfer int64 = 62

	// MaxEARFCN is the integer constant for MaxEARFCN.
	MaxEARFCN int64 = 65535

	// MaxEARFCNPlusOne is the integer constant for MaxEARFCNPlusOne.
	MaxEARFCNPlusOne int64 = 65536

	// NewmaxEARFCN is the integer constant for NewmaxEARFCN.
	NewmaxEARFCN int64 = 262143

	// MaxInterfaces is the integer constant for MaxInterfaces.
	MaxInterfaces int64 = 16

	// MaxCellineNB is the integer constant for MaxCellineNB.
	MaxCellineNB int64 = 256

	// MaxnoofBands is the integer constant for MaxnoofBands.
	MaxnoofBands int64 = 16

	// MaxnoofBearers is the integer constant for MaxnoofBearers.
	MaxnoofBearers int64 = 256

	// MaxNrOfErrors is the integer constant for MaxNrOfErrors.
	MaxNrOfErrors int64 = 256

	// MaxnoofPDCPSN is the integer constant for MaxnoofPDCPSN.
	MaxnoofPDCPSN int64 = 16

	// MaxnoofEPLMNs is the integer constant for MaxnoofEPLMNs.
	MaxnoofEPLMNs int64 = 15

	// MaxnoofEPLMNsPlusOne is the integer constant for MaxnoofEPLMNsPlusOne.
	MaxnoofEPLMNsPlusOne int64 = 16

	// MaxnoofForbLACs is the integer constant for MaxnoofForbLACs.
	MaxnoofForbLACs int64 = 4096

	// MaxnoofForbTACs is the integer constant for MaxnoofForbTACs.
	MaxnoofForbTACs int64 = 4096

	// MaxnoofBPLMNs is the integer constant for MaxnoofBPLMNs.
	MaxnoofBPLMNs int64 = 6

	// MaxnoofAdditionalPLMNs is the integer constant for MaxnoofAdditionalPLMNs.
	MaxnoofAdditionalPLMNs int64 = 6

	// MaxnoofNeighbours is the integer constant for MaxnoofNeighbours.
	MaxnoofNeighbours int64 = 512

	// MaxnoofPRBs is the integer constant for MaxnoofPRBs.
	MaxnoofPRBs int64 = 110

	// MaxPools is the integer constant for MaxPools.
	MaxPools int64 = 16

	// MaxnoofCells is the integer constant for MaxnoofCells.
	MaxnoofCells int64 = 16

	// MaxnoofMBSFN is the integer constant for MaxnoofMBSFN.
	MaxnoofMBSFN int64 = 8

	// MaxFailedMeasObjects is the integer constant for MaxFailedMeasObjects.
	MaxFailedMeasObjects int64 = 32

	// MaxnoofCellIDforMDT is the integer constant for MaxnoofCellIDforMDT.
	MaxnoofCellIDforMDT int64 = 32

	// MaxnoofTAforMDT is the integer constant for MaxnoofTAforMDT.
	MaxnoofTAforMDT int64 = 8

	// MaxnoofMBMSServiceAreaIdentities is the integer constant for MaxnoofMBMSServiceAreaIdentities.
	MaxnoofMBMSServiceAreaIdentities int64 = 256

	// MaxnoofMDTPLMNs is the integer constant for MaxnoofMDTPLMNs.
	MaxnoofMDTPLMNs int64 = 16

	// MaxnoofCoMPHypothesisSet is the integer constant for MaxnoofCoMPHypothesisSet.
	MaxnoofCoMPHypothesisSet int64 = 256

	// MaxnoofCoMPCells is the integer constant for MaxnoofCoMPCells.
	MaxnoofCoMPCells int64 = 32

	// MaxUEReport is the integer constant for MaxUEReport.
	MaxUEReport int64 = 128

	// MaxCellReport is the integer constant for MaxCellReport.
	MaxCellReport int64 = 9

	// MaxnoofPA is the integer constant for MaxnoofPA.
	MaxnoofPA int64 = 3

	// MaxCSIProcess is the integer constant for MaxCSIProcess.
	MaxCSIProcess int64 = 4

	// MaxCSIReport is the integer constant for MaxCSIReport.
	MaxCSIReport int64 = 2

	// MaxSubband is the integer constant for MaxSubband.
	MaxSubband int64 = 14

	// MaxofNRNeighbours is the integer constant for MaxofNRNeighbours.
	MaxofNRNeighbours int64 = 1024

	// MaxCellinengNB is the integer constant for MaxCellinengNB.
	MaxCellinengNB int64 = 16384

	// Maxnooftimeperiods is the integer constant for Maxnooftimeperiods.
	Maxnooftimeperiods int64 = 2

	// MaxnoofCellIDforQMC is the integer constant for MaxnoofCellIDforQMC.
	MaxnoofCellIDforQMC int64 = 32

	// MaxnoofTAforQMC is the integer constant for MaxnoofTAforQMC.
	MaxnoofTAforQMC int64 = 8

	// MaxnoofPLMNforQMC is the integer constant for MaxnoofPLMNforQMC.
	MaxnoofPLMNforQMC int64 = 16

	// MaxUEsinengNBDU is the integer constant for MaxUEsinengNBDU.
	MaxUEsinengNBDU int64 = 8192

	// MaxnoofProtectedResourcePatterns is the integer constant for MaxnoofProtectedResourcePatterns.
	MaxnoofProtectedResourcePatterns int64 = 16

	// MaxnoNRcellsSpectrumSharingWithEUTRA is the integer constant for MaxnoNRcellsSpectrumSharingWithEUTRA.
	MaxnoNRcellsSpectrumSharingWithEUTRA int64 = 64

	// MaxnoofNrCellBands is the integer constant for MaxnoofNrCellBands.
	MaxnoofNrCellBands int64 = 32

	// MaxnoofBluetoothName is the integer constant for MaxnoofBluetoothName.
	MaxnoofBluetoothName int64 = 4

	// MaxnoofWLANName is the integer constant for MaxnoofWLANName.
	MaxnoofWLANName int64 = 4

	// MaxnoofextBPLMNs is the integer constant for MaxnoofextBPLMNs.
	MaxnoofextBPLMNs int64 = 12

	// MaxnoofTLAs is the integer constant for MaxnoofTLAs.
	MaxnoofTLAs int64 = 16

	// MaxnoofGTPTLAs is the integer constant for MaxnoofGTPTLAs.
	MaxnoofGTPTLAs int64 = 16

	// MaxnoofTNLAssociations is the integer constant for MaxnoofTNLAssociations.
	MaxnoofTNLAssociations int64 = 32

	// MaxnoofCellsinCHO is the integer constant for MaxnoofCellsinCHO.
	MaxnoofCellsinCHO int64 = 8

	// MaxnoofPC5QoSFlows is the integer constant for MaxnoofPC5QoSFlows.
	MaxnoofPC5QoSFlows int64 = 2048

	// MaxnoofSSBAreas is the integer constant for MaxnoofSSBAreas.
	MaxnoofSSBAreas int64 = 64

	// MaxnoofNRSCSs is the integer constant for MaxnoofNRSCSs.
	MaxnoofNRSCSs int64 = 5

	// MaxnoofNRPhysicalResourceBlocks is the integer constant for MaxnoofNRPhysicalResourceBlocks.
	MaxnoofNRPhysicalResourceBlocks int64 = 275

	// MaxnoofNonAnchorCarrierFreqConfig is the integer constant for MaxnoofNonAnchorCarrierFreqConfig.
	MaxnoofNonAnchorCarrierFreqConfig int64 = 15

	// MaxnoofRAReports is the integer constant for MaxnoofRAReports.
	MaxnoofRAReports int64 = 64

	// MaxnoofPSCellsPerSN is the integer constant for MaxnoofPSCellsPerSN.
	MaxnoofPSCellsPerSN int64 = 8

	// MaxnoofPSCellsPerPrimaryCellinUEHistoryInfo is the integer constant for MaxnoofPSCellsPerPrimaryCellinUEHistoryInfo.
	MaxnoofPSCellsPerPrimaryCellinUEHistoryInfo int64 = 8

	// MaxnoofReportedNRCellsPossiblyAggregated is the integer constant for MaxnoofReportedNRCellsPossiblyAggregated.
	MaxnoofReportedNRCellsPossiblyAggregated int64 = 16

	// MaxnoofPSCellCandidates is the integer constant for MaxnoofPSCellCandidates.
	MaxnoofPSCellCandidates int64 = 8

	// MaxnoofTargetSgNBs is the integer constant for MaxnoofTargetSgNBs.
	MaxnoofTargetSgNBs int64 = 8

	// MaxnoofMTCItems is the integer constant for MaxnoofMTCItems.
	MaxnoofMTCItems int64 = 16

	// MaxnoofCSIRSconfigurations is the integer constant for MaxnoofCSIRSconfigurations.
	MaxnoofCSIRSconfigurations int64 = 96

	// MaxnoofCSIRSneighbourCells is the integer constant for MaxnoofCSIRSneighbourCells.
	MaxnoofCSIRSneighbourCells int64 = 16

	// MaxnoofCSIRSneighbourCellsInMTC is the integer constant for MaxnoofCSIRSneighbourCellsInMTC.
	MaxnoofCSIRSneighbourCellsInMTC int64 = 16

	// MaxnoofSensorName is the integer constant for MaxnoofSensorName.
	MaxnoofSensorName int64 = 3

	// MaxnoofTargetSgNBsMinusOne is the integer constant for MaxnoofTargetSgNBsMinusOne.
	MaxnoofTargetSgNBsMinusOne int64 = 7

	// MaxnoofUEsforRAReportIndications is the integer constant for MaxnoofUEsforRAReportIndications.
	MaxnoofUEsforRAReportIndications int64 = 64

	// IdERABsAdmittedItem is the integer constant for IdERABsAdmittedItem.
	IdERABsAdmittedItem int64 = 0

	// IdERABsAdmittedList is the integer constant for IdERABsAdmittedList.
	IdERABsAdmittedList int64 = 1

	// IdERABItem is the integer constant for IdERABItem.
	IdERABItem int64 = 2

	// IdERABsNotAdmittedList is the integer constant for IdERABsNotAdmittedList.
	IdERABsNotAdmittedList int64 = 3

	// IdERABsToBeSetupItem is the integer constant for IdERABsToBeSetupItem.
	IdERABsToBeSetupItem int64 = 4

	// IdCause is the integer constant for IdCause.
	IdCause int64 = 5

	// IdCellInformation is the integer constant for IdCellInformation.
	IdCellInformation int64 = 6

	// IdCellInformationItem is the integer constant for IdCellInformationItem.
	IdCellInformationItem int64 = 7

	// IdUnknown8 is the integer constant for IdUnknown8.
	IdUnknown8 int64 = 8

	// IdNewENBUEX2APID is the integer constant for IdNewENBUEX2APID.
	IdNewENBUEX2APID int64 = 9

	// IdOldENBUEX2APID is the integer constant for IdOldENBUEX2APID.
	IdOldENBUEX2APID int64 = 10

	// IdTargetCellID is the integer constant for IdTargetCellID.
	IdTargetCellID int64 = 11

	// IdTargeteNBtoSourceENBTransparentContainer is the integer constant for IdTargeteNBtoSourceENBTransparentContainer.
	IdTargeteNBtoSourceENBTransparentContainer int64 = 12

	// IdTraceActivation is the integer constant for IdTraceActivation.
	IdTraceActivation int64 = 13

	// IdUEContextInformation is the integer constant for IdUEContextInformation.
	IdUEContextInformation int64 = 14

	// IdUEHistoryInformation is the integer constant for IdUEHistoryInformation.
	IdUEHistoryInformation int64 = 15

	// IdUEX2APID is the integer constant for IdUEX2APID.
	IdUEX2APID int64 = 16

	// IdCriticalityDiagnostics is the integer constant for IdCriticalityDiagnostics.
	IdCriticalityDiagnostics int64 = 17

	// IdERABsSubjectToStatusTransferList is the integer constant for IdERABsSubjectToStatusTransferList.
	IdERABsSubjectToStatusTransferList int64 = 18

	// IdERABsSubjectToStatusTransferItem is the integer constant for IdERABsSubjectToStatusTransferItem.
	IdERABsSubjectToStatusTransferItem int64 = 19

	// IdServedCells is the integer constant for IdServedCells.
	IdServedCells int64 = 20

	// IdGlobalENBID is the integer constant for IdGlobalENBID.
	IdGlobalENBID int64 = 21

	// IdTimeToWait is the integer constant for IdTimeToWait.
	IdTimeToWait int64 = 22

	// IdGUMMEIID is the integer constant for IdGUMMEIID.
	IdGUMMEIID int64 = 23

	// IdGUGroupIDList is the integer constant for IdGUGroupIDList.
	IdGUGroupIDList int64 = 24

	// IdServedCellsToAdd is the integer constant for IdServedCellsToAdd.
	IdServedCellsToAdd int64 = 25

	// IdServedCellsToModify is the integer constant for IdServedCellsToModify.
	IdServedCellsToModify int64 = 26

	// IdServedCellsToDelete is the integer constant for IdServedCellsToDelete.
	IdServedCellsToDelete int64 = 27

	// IdRegistrationRequest is the integer constant for IdRegistrationRequest.
	IdRegistrationRequest int64 = 28

	// IdCellToReport is the integer constant for IdCellToReport.
	IdCellToReport int64 = 29

	// IdReportingPeriodicity is the integer constant for IdReportingPeriodicity.
	IdReportingPeriodicity int64 = 30

	// IdCellToReportItem is the integer constant for IdCellToReportItem.
	IdCellToReportItem int64 = 31

	// IdCellMeasurementResult is the integer constant for IdCellMeasurementResult.
	IdCellMeasurementResult int64 = 32

	// IdCellMeasurementResultItem is the integer constant for IdCellMeasurementResultItem.
	IdCellMeasurementResultItem int64 = 33

	// IdGUGroupIDToAddList is the integer constant for IdGUGroupIDToAddList.
	IdGUGroupIDToAddList int64 = 34

	// IdGUGroupIDToDeleteList is the integer constant for IdGUGroupIDToDeleteList.
	IdGUGroupIDToDeleteList int64 = 35

	// IdSRVCCOperationPossible is the integer constant for IdSRVCCOperationPossible.
	IdSRVCCOperationPossible int64 = 36

	// IdMeasurementID is the integer constant for IdMeasurementID.
	IdMeasurementID int64 = 37

	// IdReportCharacteristics is the integer constant for IdReportCharacteristics.
	IdReportCharacteristics int64 = 38

	// IdENB1MeasurementID is the integer constant for IdENB1MeasurementID.
	IdENB1MeasurementID int64 = 39

	// IdENB2MeasurementID is the integer constant for IdENB2MeasurementID.
	IdENB2MeasurementID int64 = 40

	// IdNumberOfAntennaports is the integer constant for IdNumberOfAntennaports.
	IdNumberOfAntennaports int64 = 41

	// IdCompositeAvailableCapacityGroup is the integer constant for IdCompositeAvailableCapacityGroup.
	IdCompositeAvailableCapacityGroup int64 = 42

	// IdENB1CellID is the integer constant for IdENB1CellID.
	IdENB1CellID int64 = 43

	// IdENB2CellID is the integer constant for IdENB2CellID.
	IdENB2CellID int64 = 44

	// IdENB2ProposedMobilityParameters is the integer constant for IdENB2ProposedMobilityParameters.
	IdENB2ProposedMobilityParameters int64 = 45

	// IdENB1MobilityParameters is the integer constant for IdENB1MobilityParameters.
	IdENB1MobilityParameters int64 = 46

	// IdENB2MobilityParametersModificationRange is the integer constant for IdENB2MobilityParametersModificationRange.
	IdENB2MobilityParametersModificationRange int64 = 47

	// IdFailureCellPCI is the integer constant for IdFailureCellPCI.
	IdFailureCellPCI int64 = 48

	// IdReEstablishmentCellECGI is the integer constant for IdReEstablishmentCellECGI.
	IdReEstablishmentCellECGI int64 = 49

	// IdFailureCellCRNTI is the integer constant for IdFailureCellCRNTI.
	IdFailureCellCRNTI int64 = 50

	// IdShortMACI is the integer constant for IdShortMACI.
	IdShortMACI int64 = 51

	// IdSourceCellECGI is the integer constant for IdSourceCellECGI.
	IdSourceCellECGI int64 = 52

	// IdFailureCellECGI is the integer constant for IdFailureCellECGI.
	IdFailureCellECGI int64 = 53

	// IdHandoverReportType is the integer constant for IdHandoverReportType.
	IdHandoverReportType int64 = 54

	// IdPRACHConfiguration is the integer constant for IdPRACHConfiguration.
	IdPRACHConfiguration int64 = 55

	// IdMBSFNSubframeInfo is the integer constant for IdMBSFNSubframeInfo.
	IdMBSFNSubframeInfo int64 = 56

	// IdServedCellsToActivate is the integer constant for IdServedCellsToActivate.
	IdServedCellsToActivate int64 = 57

	// IdActivatedCellList is the integer constant for IdActivatedCellList.
	IdActivatedCellList int64 = 58

	// IdDeactivationIndication is the integer constant for IdDeactivationIndication.
	IdDeactivationIndication int64 = 59

	// IdUERLFReportContainer is the integer constant for IdUERLFReportContainer.
	IdUERLFReportContainer int64 = 60

	// IdABSInformation is the integer constant for IdABSInformation.
	IdABSInformation int64 = 61

	// IdInvokeIndication is the integer constant for IdInvokeIndication.
	IdInvokeIndication int64 = 62

	// IdABSStatus is the integer constant for IdABSStatus.
	IdABSStatus int64 = 63

	// IdPartialSuccessIndicator is the integer constant for IdPartialSuccessIndicator.
	IdPartialSuccessIndicator int64 = 64

	// IdMeasurementInitiationResultList is the integer constant for IdMeasurementInitiationResultList.
	IdMeasurementInitiationResultList int64 = 65

	// IdMeasurementInitiationResultItem is the integer constant for IdMeasurementInitiationResultItem.
	IdMeasurementInitiationResultItem int64 = 66

	// IdMeasurementFailureCauseItem is the integer constant for IdMeasurementFailureCauseItem.
	IdMeasurementFailureCauseItem int64 = 67

	// IdCompleteFailureCauseInformationList is the integer constant for IdCompleteFailureCauseInformationList.
	IdCompleteFailureCauseInformationList int64 = 68

	// IdCompleteFailureCauseInformationItem is the integer constant for IdCompleteFailureCauseInformationItem.
	IdCompleteFailureCauseInformationItem int64 = 69

	// IdCSGId is the integer constant for IdCSGId.
	IdCSGId int64 = 70

	// IdCSGMembershipStatus is the integer constant for IdCSGMembershipStatus.
	IdCSGMembershipStatus int64 = 71

	// IdMDTConfiguration is the integer constant for IdMDTConfiguration.
	IdMDTConfiguration int64 = 72

	// IdUnknown73 is the integer constant for IdUnknown73.
	IdUnknown73 int64 = 73

	// IdManagementBasedMDTallowed is the integer constant for IdManagementBasedMDTallowed.
	IdManagementBasedMDTallowed int64 = 74

	// IdRRCConnSetupIndicator is the integer constant for IdRRCConnSetupIndicator.
	IdRRCConnSetupIndicator int64 = 75

	// IdNeighbourTAC is the integer constant for IdNeighbourTAC.
	IdNeighbourTAC int64 = 76

	// IdTimeUEStayedInCellEnhancedGranularity is the integer constant for IdTimeUEStayedInCellEnhancedGranularity.
	IdTimeUEStayedInCellEnhancedGranularity int64 = 77

	// IdRRCConnReestabIndicator is the integer constant for IdRRCConnReestabIndicator.
	IdRRCConnReestabIndicator int64 = 78

	// IdMBMSServiceAreaList is the integer constant for IdMBMSServiceAreaList.
	IdMBMSServiceAreaList int64 = 79

	// IdHOCause is the integer constant for IdHOCause.
	IdHOCause int64 = 80

	// IdTargetCellInUTRAN is the integer constant for IdTargetCellInUTRAN.
	IdTargetCellInUTRAN int64 = 81

	// IdMobilityInformation is the integer constant for IdMobilityInformation.
	IdMobilityInformation int64 = 82

	// IdSourceCellCRNTI is the integer constant for IdSourceCellCRNTI.
	IdSourceCellCRNTI int64 = 83

	// IdMultibandInfoList is the integer constant for IdMultibandInfoList.
	IdMultibandInfoList int64 = 84

	// IdM3Configuration is the integer constant for IdM3Configuration.
	IdM3Configuration int64 = 85

	// IdM4Configuration is the integer constant for IdM4Configuration.
	IdM4Configuration int64 = 86

	// IdM5Configuration is the integer constant for IdM5Configuration.
	IdM5Configuration int64 = 87

	// IdMDTLocationInfo is the integer constant for IdMDTLocationInfo.
	IdMDTLocationInfo int64 = 88

	// IdManagementBasedMDTPLMNList is the integer constant for IdManagementBasedMDTPLMNList.
	IdManagementBasedMDTPLMNList int64 = 89

	// IdSignallingBasedMDTPLMNList is the integer constant for IdSignallingBasedMDTPLMNList.
	IdSignallingBasedMDTPLMNList int64 = 90

	// IdReceiveStatusOfULPDCPSDUsExtended is the integer constant for IdReceiveStatusOfULPDCPSDUsExtended.
	IdReceiveStatusOfULPDCPSDUsExtended int64 = 91

	// IdULCOUNTValueExtended is the integer constant for IdULCOUNTValueExtended.
	IdULCOUNTValueExtended int64 = 92

	// IdDLCOUNTValueExtended is the integer constant for IdDLCOUNTValueExtended.
	IdDLCOUNTValueExtended int64 = 93

	// IdEARFCNExtension is the integer constant for IdEARFCNExtension.
	IdEARFCNExtension int64 = 94

	// IdULEARFCNExtension is the integer constant for IdULEARFCNExtension.
	IdULEARFCNExtension int64 = 95

	// IdDLEARFCNExtension is the integer constant for IdDLEARFCNExtension.
	IdDLEARFCNExtension int64 = 96

	// IdAdditionalSpecialSubframeInfo is the integer constant for IdAdditionalSpecialSubframeInfo.
	IdAdditionalSpecialSubframeInfo int64 = 97

	// IdMaskedIMEISV is the integer constant for IdMaskedIMEISV.
	IdMaskedIMEISV int64 = 98

	// IdIntendedULDLConfiguration is the integer constant for IdIntendedULDLConfiguration.
	IdIntendedULDLConfiguration int64 = 99

	// IdExtendedULInterferenceOverloadInfo is the integer constant for IdExtendedULInterferenceOverloadInfo.
	IdExtendedULInterferenceOverloadInfo int64 = 100

	// IdRNLHeader is the integer constant for IdRNLHeader.
	IdRNLHeader int64 = 101

	// IdX2APMessage is the integer constant for IdX2APMessage.
	IdX2APMessage int64 = 102

	// IdProSeAuthorized is the integer constant for IdProSeAuthorized.
	IdProSeAuthorized int64 = 103

	// IdExpectedUEBehaviour is the integer constant for IdExpectedUEBehaviour.
	IdExpectedUEBehaviour int64 = 104

	// IdUEHistoryInformationFromTheUE is the integer constant for IdUEHistoryInformationFromTheUE.
	IdUEHistoryInformationFromTheUE int64 = 105

	// IdDynamicDLTransmissionInformation is the integer constant for IdDynamicDLTransmissionInformation.
	IdDynamicDLTransmissionInformation int64 = 106

	// IdUERLFReportContainerForExtendedBands is the integer constant for IdUERLFReportContainerForExtendedBands.
	IdUERLFReportContainerForExtendedBands int64 = 107

	// IdCoMPInformation is the integer constant for IdCoMPInformation.
	IdCoMPInformation int64 = 108

	// IdReportingPeriodicityRSRPMR is the integer constant for IdReportingPeriodicityRSRPMR.
	IdReportingPeriodicityRSRPMR int64 = 109

	// IdRSRPMRList is the integer constant for IdRSRPMRList.
	IdRSRPMRList int64 = 110

	// IdMeNBUEX2APID is the integer constant for IdMeNBUEX2APID.
	IdMeNBUEX2APID int64 = 111

	// IdSeNBUEX2APID is the integer constant for IdSeNBUEX2APID.
	IdSeNBUEX2APID int64 = 112

	// IdUESecurityCapabilities is the integer constant for IdUESecurityCapabilities.
	IdUESecurityCapabilities int64 = 113

	// IdSeNBSecurityKey is the integer constant for IdSeNBSecurityKey.
	IdSeNBSecurityKey int64 = 114

	// IdSeNBUEAggregateMaximumBitRate is the integer constant for IdSeNBUEAggregateMaximumBitRate.
	IdSeNBUEAggregateMaximumBitRate int64 = 115

	// IdServingPLMN is the integer constant for IdServingPLMN.
	IdServingPLMN int64 = 116

	// IdERABsToBeAddedList is the integer constant for IdERABsToBeAddedList.
	IdERABsToBeAddedList int64 = 117

	// IdERABsToBeAddedItem is the integer constant for IdERABsToBeAddedItem.
	IdERABsToBeAddedItem int64 = 118

	// IdMeNBtoSeNBContainer is the integer constant for IdMeNBtoSeNBContainer.
	IdMeNBtoSeNBContainer int64 = 119

	// IdERABsAdmittedToBeAddedList is the integer constant for IdERABsAdmittedToBeAddedList.
	IdERABsAdmittedToBeAddedList int64 = 120

	// IdERABsAdmittedToBeAddedItem is the integer constant for IdERABsAdmittedToBeAddedItem.
	IdERABsAdmittedToBeAddedItem int64 = 121

	// IdSeNBtoMeNBContainer is the integer constant for IdSeNBtoMeNBContainer.
	IdSeNBtoMeNBContainer int64 = 122

	// IdResponseInformationSeNBReconfComp is the integer constant for IdResponseInformationSeNBReconfComp.
	IdResponseInformationSeNBReconfComp int64 = 123

	// IdUEContextInformationSeNBModReq is the integer constant for IdUEContextInformationSeNBModReq.
	IdUEContextInformationSeNBModReq int64 = 124

	// IdERABsToBeAddedModReqItem is the integer constant for IdERABsToBeAddedModReqItem.
	IdERABsToBeAddedModReqItem int64 = 125

	// IdERABsToBeModifiedModReqItem is the integer constant for IdERABsToBeModifiedModReqItem.
	IdERABsToBeModifiedModReqItem int64 = 126

	// IdERABsToBeReleasedModReqItem is the integer constant for IdERABsToBeReleasedModReqItem.
	IdERABsToBeReleasedModReqItem int64 = 127

	// IdERABsAdmittedToBeAddedModAckList is the integer constant for IdERABsAdmittedToBeAddedModAckList.
	IdERABsAdmittedToBeAddedModAckList int64 = 128

	// IdERABsAdmittedToBeModifiedModAckList is the integer constant for IdERABsAdmittedToBeModifiedModAckList.
	IdERABsAdmittedToBeModifiedModAckList int64 = 129

	// IdERABsAdmittedToBeReleasedModAckList is the integer constant for IdERABsAdmittedToBeReleasedModAckList.
	IdERABsAdmittedToBeReleasedModAckList int64 = 130

	// IdERABsAdmittedToBeAddedModAckItem is the integer constant for IdERABsAdmittedToBeAddedModAckItem.
	IdERABsAdmittedToBeAddedModAckItem int64 = 131

	// IdERABsAdmittedToBeModifiedModAckItem is the integer constant for IdERABsAdmittedToBeModifiedModAckItem.
	IdERABsAdmittedToBeModifiedModAckItem int64 = 132

	// IdERABsAdmittedToBeReleasedModAckItem is the integer constant for IdERABsAdmittedToBeReleasedModAckItem.
	IdERABsAdmittedToBeReleasedModAckItem int64 = 133

	// IdERABsToBeReleasedModReqd is the integer constant for IdERABsToBeReleasedModReqd.
	IdERABsToBeReleasedModReqd int64 = 134

	// IdERABsToBeReleasedModReqdItem is the integer constant for IdERABsToBeReleasedModReqdItem.
	IdERABsToBeReleasedModReqdItem int64 = 135

	// IdSCGChangeIndication is the integer constant for IdSCGChangeIndication.
	IdSCGChangeIndication int64 = 136

	// IdERABsToBeReleasedListRelReq is the integer constant for IdERABsToBeReleasedListRelReq.
	IdERABsToBeReleasedListRelReq int64 = 137

	// IdERABsToBeReleasedRelReqItem is the integer constant for IdERABsToBeReleasedRelReqItem.
	IdERABsToBeReleasedRelReqItem int64 = 138

	// IdERABsToBeReleasedListRelConf is the integer constant for IdERABsToBeReleasedListRelConf.
	IdERABsToBeReleasedListRelConf int64 = 139

	// IdERABsToBeReleasedRelConfItem is the integer constant for IdERABsToBeReleasedRelConfItem.
	IdERABsToBeReleasedRelConfItem int64 = 140

	// IdERABsSubjectToCounterCheckList is the integer constant for IdERABsSubjectToCounterCheckList.
	IdERABsSubjectToCounterCheckList int64 = 141

	// IdERABsSubjectToCounterCheckItem is the integer constant for IdERABsSubjectToCounterCheckItem.
	IdERABsSubjectToCounterCheckItem int64 = 142

	// IdCoverageModificationList is the integer constant for IdCoverageModificationList.
	IdCoverageModificationList int64 = 143

	// IdUnknown144 is the integer constant for IdUnknown144.
	IdUnknown144 int64 = 144

	// IdReportingPeriodicityCSIR is the integer constant for IdReportingPeriodicityCSIR.
	IdReportingPeriodicityCSIR int64 = 145

	// IdCSIReportList is the integer constant for IdCSIReportList.
	IdCSIReportList int64 = 146

	// IdUEID is the integer constant for IdUEID.
	IdUEID int64 = 147

	// IdEnhancedRNTP is the integer constant for IdEnhancedRNTP.
	IdEnhancedRNTP int64 = 148

	// IdProSeUEtoNetworkRelaying is the integer constant for IdProSeUEtoNetworkRelaying.
	IdProSeUEtoNetworkRelaying int64 = 149

	// IdReceiveStatusOfULPDCPSDUsPDCPSNlength18 is the integer constant for IdReceiveStatusOfULPDCPSDUsPDCPSNlength18.
	IdReceiveStatusOfULPDCPSDUsPDCPSNlength18 int64 = 150

	// IdULCOUNTValuePDCPSNlength18 is the integer constant for IdULCOUNTValuePDCPSNlength18.
	IdULCOUNTValuePDCPSNlength18 int64 = 151

	// IdDLCOUNTValuePDCPSNlength18 is the integer constant for IdDLCOUNTValuePDCPSNlength18.
	IdDLCOUNTValuePDCPSNlength18 int64 = 152

	// IdUEContextReferenceAtSeNB is the integer constant for IdUEContextReferenceAtSeNB.
	IdUEContextReferenceAtSeNB int64 = 153

	// IdUEContextKeptIndicator is the integer constant for IdUEContextKeptIndicator.
	IdUEContextKeptIndicator int64 = 154

	// IdNewENBUEX2APIDExtension is the integer constant for IdNewENBUEX2APIDExtension.
	IdNewENBUEX2APIDExtension int64 = 155

	// IdOldENBUEX2APIDExtension is the integer constant for IdOldENBUEX2APIDExtension.
	IdOldENBUEX2APIDExtension int64 = 156

	// IdMeNBUEX2APIDExtension is the integer constant for IdMeNBUEX2APIDExtension.
	IdMeNBUEX2APIDExtension int64 = 157

	// IdSeNBUEX2APIDExtension is the integer constant for IdSeNBUEX2APIDExtension.
	IdSeNBUEX2APIDExtension int64 = 158

	// IdLHNID is the integer constant for IdLHNID.
	IdLHNID int64 = 159

	// IdFreqBandIndicatorPriority is the integer constant for IdFreqBandIndicatorPriority.
	IdFreqBandIndicatorPriority int64 = 160

	// IdM6Configuration is the integer constant for IdM6Configuration.
	IdM6Configuration int64 = 161

	// IdM7Configuration is the integer constant for IdM7Configuration.
	IdM7Configuration int64 = 162

	// IdTunnelInformationForBBF is the integer constant for IdTunnelInformationForBBF.
	IdTunnelInformationForBBF int64 = 163

	// IdSIPTOBearerDeactivationIndication is the integer constant for IdSIPTOBearerDeactivationIndication.
	IdSIPTOBearerDeactivationIndication int64 = 164

	// IdGWTransportLayerAddress is the integer constant for IdGWTransportLayerAddress.
	IdGWTransportLayerAddress int64 = 165

	// IdCorrelationID is the integer constant for IdCorrelationID.
	IdCorrelationID int64 = 166

	// IdSIPTOCorrelationID is the integer constant for IdSIPTOCorrelationID.
	IdSIPTOCorrelationID int64 = 167

	// IdSIPTOLGWTransportLayerAddress is the integer constant for IdSIPTOLGWTransportLayerAddress.
	IdSIPTOLGWTransportLayerAddress int64 = 168

	// IdX2RemovalThreshold is the integer constant for IdX2RemovalThreshold.
	IdX2RemovalThreshold int64 = 169

	// IdCellReportingIndicator is the integer constant for IdCellReportingIndicator.
	IdCellReportingIndicator int64 = 170

	// IdBearerType is the integer constant for IdBearerType.
	IdBearerType int64 = 171

	// IdResumeID is the integer constant for IdResumeID.
	IdResumeID int64 = 172

	// IdUEContextInformationRetrieve is the integer constant for IdUEContextInformationRetrieve.
	IdUEContextInformationRetrieve int64 = 173

	// IdERABsToBeSetupRetrieveItem is the integer constant for IdERABsToBeSetupRetrieveItem.
	IdERABsToBeSetupRetrieveItem int64 = 174

	// IdNewEUTRANCellIdentifier is the integer constant for IdNewEUTRANCellIdentifier.
	IdNewEUTRANCellIdentifier int64 = 175

	// IdV2XServicesAuthorized is the integer constant for IdV2XServicesAuthorized.
	IdV2XServicesAuthorized int64 = 176

	// IdOffsetOfNbiotChannelNumberToDLEARFCN is the integer constant for IdOffsetOfNbiotChannelNumberToDLEARFCN.
	IdOffsetOfNbiotChannelNumberToDLEARFCN int64 = 177

	// IdOffsetOfNbiotChannelNumberToULEARFCN is the integer constant for IdOffsetOfNbiotChannelNumberToULEARFCN.
	IdOffsetOfNbiotChannelNumberToULEARFCN int64 = 178

	// IdAdditionalSpecialSubframeExtensionInfo is the integer constant for IdAdditionalSpecialSubframeExtensionInfo.
	IdAdditionalSpecialSubframeExtensionInfo int64 = 179

	// IdBandwidthReducedSI is the integer constant for IdBandwidthReducedSI.
	IdBandwidthReducedSI int64 = 180

	// IdMakeBeforeBreakIndicator is the integer constant for IdMakeBeforeBreakIndicator.
	IdMakeBeforeBreakIndicator int64 = 181

	// IdUEContextReferenceAtWT is the integer constant for IdUEContextReferenceAtWT.
	IdUEContextReferenceAtWT int64 = 182

	// IdWTUEContextKeptIndicator is the integer constant for IdWTUEContextKeptIndicator.
	IdWTUEContextKeptIndicator int64 = 183

	// IdUESidelinkAggregateMaximumBitRate is the integer constant for IdUESidelinkAggregateMaximumBitRate.
	IdUESidelinkAggregateMaximumBitRate int64 = 184

	// IdULGTPtunnelEndpoint is the integer constant for IdULGTPtunnelEndpoint.
	IdULGTPtunnelEndpoint int64 = 185

	// IdUnknown186 is the integer constant for IdUnknown186.
	IdUnknown186 int64 = 186

	// IdUnknown187 is the integer constant for IdUnknown187.
	IdUnknown187 int64 = 187

	// IdUnknown188 is the integer constant for IdUnknown188.
	IdUnknown188 int64 = 188

	// IdUnknown189 is the integer constant for IdUnknown189.
	IdUnknown189 int64 = 189

	// IdUnknown190 is the integer constant for IdUnknown190.
	IdUnknown190 int64 = 190

	// IdUnknown191 is the integer constant for IdUnknown191.
	IdUnknown191 int64 = 191

	// IdUnknown192 is the integer constant for IdUnknown192.
	IdUnknown192 int64 = 192

	// IdDLSchedulingPDCCHCCEUsage is the integer constant for IdDLSchedulingPDCCHCCEUsage.
	IdDLSchedulingPDCCHCCEUsage int64 = 193

	// IdULSchedulingPDCCHCCEUsage is the integer constant for IdULSchedulingPDCCHCCEUsage.
	IdULSchedulingPDCCHCCEUsage int64 = 194

	// IdUEAppLayerMeasConfig is the integer constant for IdUEAppLayerMeasConfig.
	IdUEAppLayerMeasConfig int64 = 195

	// IdExtendedERABMaximumBitrateDL is the integer constant for IdExtendedERABMaximumBitrateDL.
	IdExtendedERABMaximumBitrateDL int64 = 196

	// IdExtendedERABMaximumBitrateUL is the integer constant for IdExtendedERABMaximumBitrateUL.
	IdExtendedERABMaximumBitrateUL int64 = 197

	// IdExtendedERABGuaranteedBitrateDL is the integer constant for IdExtendedERABGuaranteedBitrateDL.
	IdExtendedERABGuaranteedBitrateDL int64 = 198

	// IdExtendedERABGuaranteedBitrateUL is the integer constant for IdExtendedERABGuaranteedBitrateUL.
	IdExtendedERABGuaranteedBitrateUL int64 = 199

	// IdExtendedUEaggregateMaximumBitRateDownlink is the integer constant for IdExtendedUEaggregateMaximumBitRateDownlink.
	IdExtendedUEaggregateMaximumBitRateDownlink int64 = 200

	// IdExtendedUEaggregateMaximumBitRateUplink is the integer constant for IdExtendedUEaggregateMaximumBitRateUplink.
	IdExtendedUEaggregateMaximumBitRateUplink int64 = 201

	// IdNRrestrictioninEPSasSecondaryRAT is the integer constant for IdNRrestrictioninEPSasSecondaryRAT.
	IdNRrestrictioninEPSasSecondaryRAT int64 = 202

	// IdSgNBSecurityKey is the integer constant for IdSgNBSecurityKey.
	IdSgNBSecurityKey int64 = 203

	// IdSgNBUEAggregateMaximumBitRate is the integer constant for IdSgNBUEAggregateMaximumBitRate.
	IdSgNBUEAggregateMaximumBitRate int64 = 204

	// IdERABsToBeAddedSgNBAddReqList is the integer constant for IdERABsToBeAddedSgNBAddReqList.
	IdERABsToBeAddedSgNBAddReqList int64 = 205

	// IdMeNBtoSgNBContainer is the integer constant for IdMeNBtoSgNBContainer.
	IdMeNBtoSgNBContainer int64 = 206

	// IdSgNBUEX2APID is the integer constant for IdSgNBUEX2APID.
	IdSgNBUEX2APID int64 = 207

	// IdRequestedSplitSRBs is the integer constant for IdRequestedSplitSRBs.
	IdRequestedSplitSRBs int64 = 208

	// IdERABsToBeAddedSgNBAddReqItem is the integer constant for IdERABsToBeAddedSgNBAddReqItem.
	IdERABsToBeAddedSgNBAddReqItem int64 = 209

	// IdERABsAdmittedToBeAddedSgNBAddReqAckList is the integer constant for IdERABsAdmittedToBeAddedSgNBAddReqAckList.
	IdERABsAdmittedToBeAddedSgNBAddReqAckList int64 = 210

	// IdSgNBtoMeNBContainer is the integer constant for IdSgNBtoMeNBContainer.
	IdSgNBtoMeNBContainer int64 = 211

	// IdAdmittedSplitSRBs is the integer constant for IdAdmittedSplitSRBs.
	IdAdmittedSplitSRBs int64 = 212

	// IdERABsAdmittedToBeAddedSgNBAddReqAckItem is the integer constant for IdERABsAdmittedToBeAddedSgNBAddReqAckItem.
	IdERABsAdmittedToBeAddedSgNBAddReqAckItem int64 = 213

	// IdResponseInformationSgNBReconfComp is the integer constant for IdResponseInformationSgNBReconfComp.
	IdResponseInformationSgNBReconfComp int64 = 214

	// IdUEContextInformationSgNBModReq is the integer constant for IdUEContextInformationSgNBModReq.
	IdUEContextInformationSgNBModReq int64 = 215

	// IdERABsToBeAddedSgNBModReqItem is the integer constant for IdERABsToBeAddedSgNBModReqItem.
	IdERABsToBeAddedSgNBModReqItem int64 = 216

	// IdERABsToBeModifiedSgNBModReqItem is the integer constant for IdERABsToBeModifiedSgNBModReqItem.
	IdERABsToBeModifiedSgNBModReqItem int64 = 217

	// IdERABsToBeReleasedSgNBModReqItem is the integer constant for IdERABsToBeReleasedSgNBModReqItem.
	IdERABsToBeReleasedSgNBModReqItem int64 = 218

	// IdERABsAdmittedToBeAddedSgNBModAckList is the integer constant for IdERABsAdmittedToBeAddedSgNBModAckList.
	IdERABsAdmittedToBeAddedSgNBModAckList int64 = 219

	// IdERABsAdmittedToBeModifiedSgNBModAckList is the integer constant for IdERABsAdmittedToBeModifiedSgNBModAckList.
	IdERABsAdmittedToBeModifiedSgNBModAckList int64 = 220

	// IdERABsAdmittedToBeReleasedSgNBModAckList is the integer constant for IdERABsAdmittedToBeReleasedSgNBModAckList.
	IdERABsAdmittedToBeReleasedSgNBModAckList int64 = 221

	// IdERABsAdmittedToBeAddedSgNBModAckItem is the integer constant for IdERABsAdmittedToBeAddedSgNBModAckItem.
	IdERABsAdmittedToBeAddedSgNBModAckItem int64 = 222

	// IdERABsAdmittedToBeModifiedSgNBModAckItem is the integer constant for IdERABsAdmittedToBeModifiedSgNBModAckItem.
	IdERABsAdmittedToBeModifiedSgNBModAckItem int64 = 223

	// IdERABsAdmittedToBeReleasedSgNBModAckItem is the integer constant for IdERABsAdmittedToBeReleasedSgNBModAckItem.
	IdERABsAdmittedToBeReleasedSgNBModAckItem int64 = 224

	// IdERABsToBeReleasedSgNBModReqdList is the integer constant for IdERABsToBeReleasedSgNBModReqdList.
	IdERABsToBeReleasedSgNBModReqdList int64 = 225

	// IdERABsToBeModifiedSgNBModReqdList is the integer constant for IdERABsToBeModifiedSgNBModReqdList.
	IdERABsToBeModifiedSgNBModReqdList int64 = 226

	// IdERABsToBeReleasedSgNBModReqdItem is the integer constant for IdERABsToBeReleasedSgNBModReqdItem.
	IdERABsToBeReleasedSgNBModReqdItem int64 = 227

	// IdERABsToBeModifiedSgNBModReqdItem is the integer constant for IdERABsToBeModifiedSgNBModReqdItem.
	IdERABsToBeModifiedSgNBModReqdItem int64 = 228

	// IdERABsToBeReleasedSgNBChaConfList is the integer constant for IdERABsToBeReleasedSgNBChaConfList.
	IdERABsToBeReleasedSgNBChaConfList int64 = 229

	// IdERABsToBeReleasedSgNBChaConfItem is the integer constant for IdERABsToBeReleasedSgNBChaConfItem.
	IdERABsToBeReleasedSgNBChaConfItem int64 = 230

	// IdERABsToBeReleasedSgNBRelReqList is the integer constant for IdERABsToBeReleasedSgNBRelReqList.
	IdERABsToBeReleasedSgNBRelReqList int64 = 231

	// IdERABsToBeReleasedSgNBRelReqItem is the integer constant for IdERABsToBeReleasedSgNBRelReqItem.
	IdERABsToBeReleasedSgNBRelReqItem int64 = 232

	// IdERABsToBeReleasedSgNBRelConfList is the integer constant for IdERABsToBeReleasedSgNBRelConfList.
	IdERABsToBeReleasedSgNBRelConfList int64 = 233

	// IdERABsToBeReleasedSgNBRelConfItem is the integer constant for IdERABsToBeReleasedSgNBRelConfItem.
	IdERABsToBeReleasedSgNBRelConfItem int64 = 234

	// IdERABsSubjectToSgNBCounterCheckList is the integer constant for IdERABsSubjectToSgNBCounterCheckList.
	IdERABsSubjectToSgNBCounterCheckList int64 = 235

	// IdERABsSubjectToSgNBCounterCheckItem is the integer constant for IdERABsSubjectToSgNBCounterCheckItem.
	IdERABsSubjectToSgNBCounterCheckItem int64 = 236

	// IdRRCContainer is the integer constant for IdRRCContainer.
	IdRRCContainer int64 = 237

	// IdSRBType is the integer constant for IdSRBType.
	IdSRBType int64 = 238

	// IdTargetSgNBID is the integer constant for IdTargetSgNBID.
	IdTargetSgNBID int64 = 239

	// IdHandoverRestrictionList is the integer constant for IdHandoverRestrictionList.
	IdHandoverRestrictionList int64 = 240

	// IdSCGConfigurationQuery is the integer constant for IdSCGConfigurationQuery.
	IdSCGConfigurationQuery int64 = 241

	// IdSplitSRB is the integer constant for IdSplitSRB.
	IdSplitSRB int64 = 242

	// IdNRUeReport is the integer constant for IdNRUeReport.
	IdNRUeReport int64 = 243

	// IdInitiatingNodeTypeEndcX2Setup is the integer constant for IdInitiatingNodeTypeEndcX2Setup.
	IdInitiatingNodeTypeEndcX2Setup int64 = 244

	// IdInitiatingNodeTypeEndcConfigUpdate is the integer constant for IdInitiatingNodeTypeEndcConfigUpdate.
	IdInitiatingNodeTypeEndcConfigUpdate int64 = 245

	// IdRespondingNodeTypeEndcX2Setup is the integer constant for IdRespondingNodeTypeEndcX2Setup.
	IdRespondingNodeTypeEndcX2Setup int64 = 246

	// IdRespondingNodeTypeEndcConfigUpdate is the integer constant for IdRespondingNodeTypeEndcConfigUpdate.
	IdRespondingNodeTypeEndcConfigUpdate int64 = 247

	// IdNRUESecurityCapabilities is the integer constant for IdNRUESecurityCapabilities.
	IdNRUESecurityCapabilities int64 = 248

	// IdPDCPChangeIndication is the integer constant for IdPDCPChangeIndication.
	IdPDCPChangeIndication int64 = 249

	// IdServedEUTRAcellsENDCX2ManagementList is the integer constant for IdServedEUTRAcellsENDCX2ManagementList.
	IdServedEUTRAcellsENDCX2ManagementList int64 = 250

	// IdCellAssistanceInformation is the integer constant for IdCellAssistanceInformation.
	IdCellAssistanceInformation int64 = 251

	// IdGlobalenGNBID is the integer constant for IdGlobalenGNBID.
	IdGlobalenGNBID int64 = 252

	// IdServedNRcellsENDCX2ManagementList is the integer constant for IdServedNRcellsENDCX2ManagementList.
	IdServedNRcellsENDCX2ManagementList int64 = 253

	// IdUEContextReferenceAtSgNB is the integer constant for IdUEContextReferenceAtSgNB.
	IdUEContextReferenceAtSgNB int64 = 254

	// IdSecondaryRATUsageReport is the integer constant for IdSecondaryRATUsageReport.
	IdSecondaryRATUsageReport int64 = 255

	// IdActivationID is the integer constant for IdActivationID.
	IdActivationID int64 = 256

	// IdMeNBResourceCoordinationInformation is the integer constant for IdMeNBResourceCoordinationInformation.
	IdMeNBResourceCoordinationInformation int64 = 257

	// IdSgNBResourceCoordinationInformation is the integer constant for IdSgNBResourceCoordinationInformation.
	IdSgNBResourceCoordinationInformation int64 = 258

	// IdServedEUTRAcellsToModifyListENDCConfUpd is the integer constant for IdServedEUTRAcellsToModifyListENDCConfUpd.
	IdServedEUTRAcellsToModifyListENDCConfUpd int64 = 259

	// IdServedEUTRAcellsToDeleteListENDCConfUpd is the integer constant for IdServedEUTRAcellsToDeleteListENDCConfUpd.
	IdServedEUTRAcellsToDeleteListENDCConfUpd int64 = 260

	// IdServedNRcellsToModifyListENDCConfUpd is the integer constant for IdServedNRcellsToModifyListENDCConfUpd.
	IdServedNRcellsToModifyListENDCConfUpd int64 = 261

	// IdServedNRcellsToDeleteListENDCConfUpd is the integer constant for IdServedNRcellsToDeleteListENDCConfUpd.
	IdServedNRcellsToDeleteListENDCConfUpd int64 = 262

	// IdERABUsageReportItem is the integer constant for IdERABUsageReportItem.
	IdERABUsageReportItem int64 = 263

	// IdOldSgNBUEX2APID is the integer constant for IdOldSgNBUEX2APID.
	IdOldSgNBUEX2APID int64 = 264

	// IdSecondaryRATUsageReportList is the integer constant for IdSecondaryRATUsageReportList.
	IdSecondaryRATUsageReportList int64 = 265

	// IdSecondaryRATUsageReportItem is the integer constant for IdSecondaryRATUsageReportItem.
	IdSecondaryRATUsageReportItem int64 = 266

	// IdServedNRCellsToActivate is the integer constant for IdServedNRCellsToActivate.
	IdServedNRCellsToActivate int64 = 267

	// IdActivatedNRCellList is the integer constant for IdActivatedNRCellList.
	IdActivatedNRCellList int64 = 268

	// IdSelectedPLMN is the integer constant for IdSelectedPLMN.
	IdSelectedPLMN int64 = 269

	// IdUEsToBeReset is the integer constant for IdUEsToBeReset.
	IdUEsToBeReset int64 = 270

	// IdUEsAdmittedToBeReset is the integer constant for IdUEsAdmittedToBeReset.
	IdUEsAdmittedToBeReset int64 = 271

	// IdRRCConfigIndication is the integer constant for IdRRCConfigIndication.
	IdRRCConfigIndication int64 = 272

	// IdDownlinkPacketLossRate is the integer constant for IdDownlinkPacketLossRate.
	IdDownlinkPacketLossRate int64 = 273

	// IdUplinkPacketLossRate is the integer constant for IdUplinkPacketLossRate.
	IdUplinkPacketLossRate int64 = 274

	// IdSubscriberProfileIDforRFP is the integer constant for IdSubscriberProfileIDforRFP.
	IdSubscriberProfileIDforRFP int64 = 275

	// IdServiceType is the integer constant for IdServiceType.
	IdServiceType int64 = 276

	// IdAerialUEsubscriptionInformation is the integer constant for IdAerialUEsubscriptionInformation.
	IdAerialUEsubscriptionInformation int64 = 277

	// IdSGNBAdditionTriggerInd is the integer constant for IdSGNBAdditionTriggerInd.
	IdSGNBAdditionTriggerInd int64 = 278

	// IdMeNBCellID is the integer constant for IdMeNBCellID.
	IdMeNBCellID int64 = 279

	// IdRequestedSplitSRBsrelease is the integer constant for IdRequestedSplitSRBsrelease.
	IdRequestedSplitSRBsrelease int64 = 280

	// IdAdmittedSplitSRBsrelease is the integer constant for IdAdmittedSplitSRBsrelease.
	IdAdmittedSplitSRBsrelease int64 = 281

	// IdNRSNSSSPowerOffset is the integer constant for IdNRSNSSSPowerOffset.
	IdNRSNSSSPowerOffset int64 = 282

	// IdNSSSNumOccasionDifferentPrecoder is the integer constant for IdNSSSNumOccasionDifferentPrecoder.
	IdNSSSNumOccasionDifferentPrecoder int64 = 283

	// IdProtectedEUTRAResourceIndication is the integer constant for IdProtectedEUTRAResourceIndication.
	IdProtectedEUTRAResourceIndication int64 = 284

	// IdInitiatingNodeTypeEutranrCellResourceCoordination is the integer constant for IdInitiatingNodeTypeEutranrCellResourceCoordination.
	IdInitiatingNodeTypeEutranrCellResourceCoordination int64 = 285

	// IdRespondingNodeTypeEutranrCellResourceCoordination is the integer constant for IdRespondingNodeTypeEutranrCellResourceCoordination.
	IdRespondingNodeTypeEutranrCellResourceCoordination int64 = 286

	// IdDataTrafficResourceIndication is the integer constant for IdDataTrafficResourceIndication.
	IdDataTrafficResourceIndication int64 = 287

	// IdSpectrumSharingGroupID is the integer constant for IdSpectrumSharingGroupID.
	IdSpectrumSharingGroupID int64 = 288

	// IdListofEUTRACellsinEUTRACoordinationReq is the integer constant for IdListofEUTRACellsinEUTRACoordinationReq.
	IdListofEUTRACellsinEUTRACoordinationReq int64 = 289

	// IdListofEUTRACellsinEUTRACoordinationResp is the integer constant for IdListofEUTRACellsinEUTRACoordinationResp.
	IdListofEUTRACellsinEUTRACoordinationResp int64 = 290

	// IdListofEUTRACellsinNRCoordinationReq is the integer constant for IdListofEUTRACellsinNRCoordinationReq.
	IdListofEUTRACellsinNRCoordinationReq int64 = 291

	// IdListofNRCellsinNRCoordinationReq is the integer constant for IdListofNRCellsinNRCoordinationReq.
	IdListofNRCellsinNRCoordinationReq int64 = 292

	// IdListofNRCellsinNRCoordinationResp is the integer constant for IdListofNRCellsinNRCoordinationResp.
	IdListofNRCellsinNRCoordinationResp int64 = 293

	// IdERABsAdmittedToBeModifiedSgNBModConfList is the integer constant for IdERABsAdmittedToBeModifiedSgNBModConfList.
	IdERABsAdmittedToBeModifiedSgNBModConfList int64 = 294

	// IdERABsAdmittedToBeModifiedSgNBModConfItem is the integer constant for IdERABsAdmittedToBeModifiedSgNBModConfItem.
	IdERABsAdmittedToBeModifiedSgNBModConfItem int64 = 295

	// IdUEContextLevelUserPlaneActivity is the integer constant for IdUEContextLevelUserPlaneActivity.
	IdUEContextLevelUserPlaneActivity int64 = 296

	// IdERABActivityNotifyItemList is the integer constant for IdERABActivityNotifyItemList.
	IdERABActivityNotifyItemList int64 = 297

	// IdInitiatingNodeTypeEndcX2Removal is the integer constant for IdInitiatingNodeTypeEndcX2Removal.
	IdInitiatingNodeTypeEndcX2Removal int64 = 298

	// IdRespondingNodeTypeEndcX2Removal is the integer constant for IdRespondingNodeTypeEndcX2Removal.
	IdRespondingNodeTypeEndcX2Removal int64 = 299

	// IdRLCStatus is the integer constant for IdRLCStatus.
	IdRLCStatus int64 = 300

	// IdCNTypeRestrictions is the integer constant for IdCNTypeRestrictions.
	IdCNTypeRestrictions int64 = 301

	// IdULpDCPSnLength is the integer constant for IdULpDCPSnLength.
	IdULpDCPSnLength int64 = 302

	// IdBluetoothMeasurementConfiguration is the integer constant for IdBluetoothMeasurementConfiguration.
	IdBluetoothMeasurementConfiguration int64 = 303

	// IdWLANMeasurementConfiguration is the integer constant for IdWLANMeasurementConfiguration.
	IdWLANMeasurementConfiguration int64 = 304

	// IdNRrestrictionin5GS is the integer constant for IdNRrestrictionin5GS.
	IdNRrestrictionin5GS int64 = 305

	// IdDLForwarding is the integer constant for IdDLForwarding.
	IdDLForwarding int64 = 306

	// IdERABsDataForwardingAddressList is the integer constant for IdERABsDataForwardingAddressList.
	IdERABsDataForwardingAddressList int64 = 307

	// IdERABsDataForwardingAddressItem is the integer constant for IdERABsDataForwardingAddressItem.
	IdERABsDataForwardingAddressItem int64 = 308

	// IdSubscriptionBasedUEDifferentiationInfo is the integer constant for IdSubscriptionBasedUEDifferentiationInfo.
	IdSubscriptionBasedUEDifferentiationInfo int64 = 309

	// IdGNBOverloadInformation is the integer constant for IdGNBOverloadInformation.
	IdGNBOverloadInformation int64 = 310

	// IdDLPDCPSnLength is the integer constant for IdDLPDCPSnLength.
	IdDLPDCPSnLength int64 = 311

	// IdSecondarysgNBDLGTPTEIDatPDCP is the integer constant for IdSecondarysgNBDLGTPTEIDatPDCP.
	IdSecondarysgNBDLGTPTEIDatPDCP int64 = 312

	// IdSecondarymeNBULGTPTEIDatPDCP is the integer constant for IdSecondarymeNBULGTPTEIDatPDCP.
	IdSecondarymeNBULGTPTEIDatPDCP int64 = 313

	// IdLCID is the integer constant for IdLCID.
	IdLCID int64 = 314

	// IdDuplicationActivation is the integer constant for IdDuplicationActivation.
	IdDuplicationActivation int64 = 315

	// IdECGI is the integer constant for IdECGI.
	IdECGI int64 = 316

	// IdRLCModeTransferred is the integer constant for IdRLCModeTransferred.
	IdRLCModeTransferred int64 = 317

	// IdERABsAdmittedToBeReleasedSgNBRelReqAckList is the integer constant for IdERABsAdmittedToBeReleasedSgNBRelReqAckList.
	IdERABsAdmittedToBeReleasedSgNBRelReqAckList int64 = 318

	// IdERABsAdmittedToBeReleasedSgNBRelReqAckItem is the integer constant for IdERABsAdmittedToBeReleasedSgNBRelReqAckItem.
	IdERABsAdmittedToBeReleasedSgNBRelReqAckItem int64 = 319

	// IdERABsToBeReleasedSgNBRelReqdList is the integer constant for IdERABsToBeReleasedSgNBRelReqdList.
	IdERABsToBeReleasedSgNBRelReqdList int64 = 320

	// IdERABsToBeReleasedSgNBRelReqdItem is the integer constant for IdERABsToBeReleasedSgNBRelReqdItem.
	IdERABsToBeReleasedSgNBRelReqdItem int64 = 321

	// IdNRCGI is the integer constant for IdNRCGI.
	IdNRCGI int64 = 322

	// IdMeNBCoordinationAssistanceInformation is the integer constant for IdMeNBCoordinationAssistanceInformation.
	IdMeNBCoordinationAssistanceInformation int64 = 323

	// IdSgNBCoordinationAssistanceInformation is the integer constant for IdSgNBCoordinationAssistanceInformation.
	IdSgNBCoordinationAssistanceInformation int64 = 324

	// IdNewDrbIDReq is the integer constant for IdNewDrbIDReq.
	IdNewDrbIDReq int64 = 325

	// IdEndcSONConfigurationTransfer is the integer constant for IdEndcSONConfigurationTransfer.
	IdEndcSONConfigurationTransfer int64 = 326

	// IdNRNeighbourInfoToAdd is the integer constant for IdNRNeighbourInfoToAdd.
	IdNRNeighbourInfoToAdd int64 = 327

	// IdNRNeighbourInfoToModify is the integer constant for IdNRNeighbourInfoToModify.
	IdNRNeighbourInfoToModify int64 = 328

	// IdDesiredActNotificationLevel is the integer constant for IdDesiredActNotificationLevel.
	IdDesiredActNotificationLevel int64 = 329

	// IdLocationInformationSgNBReporting is the integer constant for IdLocationInformationSgNBReporting.
	IdLocationInformationSgNBReporting int64 = 330

	// IdLocationInformationSgNB is the integer constant for IdLocationInformationSgNB.
	IdLocationInformationSgNB int64 = 331

	// IdLastNGRANPLMNIdentity is the integer constant for IdLastNGRANPLMNIdentity.
	IdLastNGRANPLMNIdentity int64 = 332

	// IdEUTRANTraceID is the integer constant for IdEUTRANTraceID.
	IdEUTRANTraceID int64 = 333

	// IdAdditionalPLMNsItem is the integer constant for IdAdditionalPLMNsItem.
	IdAdditionalPLMNsItem int64 = 334

	// IdInterfaceInstanceIndication is the integer constant for IdInterfaceInstanceIndication.
	IdInterfaceInstanceIndication int64 = 335

	// IdBPLMNIDInfoEUTRA is the integer constant for IdBPLMNIDInfoEUTRA.
	IdBPLMNIDInfoEUTRA int64 = 336

	// IdBPLMNIDInfoNR is the integer constant for IdBPLMNIDInfoNR.
	IdBPLMNIDInfoNR int64 = 337

	// IdNBIoTULDLAlignmentOffset is the integer constant for IdNBIoTULDLAlignmentOffset.
	IdNBIoTULDLAlignmentOffset int64 = 338

	// IdERABsTransferredToMeNB is the integer constant for IdERABsTransferredToMeNB.
	IdERABsTransferredToMeNB int64 = 339

	// IdAdditionalRRMPriorityIndex is the integer constant for IdAdditionalRRMPriorityIndex.
	IdAdditionalRRMPriorityIndex int64 = 340

	// IdLowerLayerPresenceStatusChange is the integer constant for IdLowerLayerPresenceStatusChange.
	IdLowerLayerPresenceStatusChange int64 = 341

	// IdFastMCGRecoverySNToMN is the integer constant for IdFastMCGRecoverySNToMN.
	IdFastMCGRecoverySNToMN int64 = 342

	// IdRequestedFastMCGRecoveryViaSRB3 is the integer constant for IdRequestedFastMCGRecoveryViaSRB3.
	IdRequestedFastMCGRecoveryViaSRB3 int64 = 343

	// IdAvailableFastMCGRecoveryViaSRB3 is the integer constant for IdAvailableFastMCGRecoveryViaSRB3.
	IdAvailableFastMCGRecoveryViaSRB3 int64 = 344

	// IdRequestedFastMCGRecoveryViaSRB3Release is the integer constant for IdRequestedFastMCGRecoveryViaSRB3Release.
	IdRequestedFastMCGRecoveryViaSRB3Release int64 = 345

	// IdReleaseFastMCGRecoveryViaSRB3 is the integer constant for IdReleaseFastMCGRecoveryViaSRB3.
	IdReleaseFastMCGRecoveryViaSRB3 int64 = 346

	// IdFastMCGRecoveryMNToSN is the integer constant for IdFastMCGRecoveryMNToSN.
	IdFastMCGRecoveryMNToSN int64 = 347

	// IdPartialListIndicator is the integer constant for IdPartialListIndicator.
	IdPartialListIndicator int64 = 348

	// IdMaximumCellListSize is the integer constant for IdMaximumCellListSize.
	IdMaximumCellListSize int64 = 349

	// IdMessageOversizeNotification is the integer constant for IdMessageOversizeNotification.
	IdMessageOversizeNotification int64 = 350

	// IdCellandCapacityAssistInfo is the integer constant for IdCellandCapacityAssistInfo.
	IdCellandCapacityAssistInfo int64 = 351

	// IdTNLConfigurationInfo is the integer constant for IdTNLConfigurationInfo.
	IdTNLConfigurationInfo int64 = 352

	// IdTNLAToAddList is the integer constant for IdTNLAToAddList.
	IdTNLAToAddList int64 = 353

	// IdTNLAToUpdateList is the integer constant for IdTNLAToUpdateList.
	IdTNLAToUpdateList int64 = 354

	// IdTNLAToRemoveList is the integer constant for IdTNLAToRemoveList.
	IdTNLAToRemoveList int64 = 355

	// IdTNLASetupList is the integer constant for IdTNLASetupList.
	IdTNLASetupList int64 = 356

	// IdTNLAFailedToSetupList is the integer constant for IdTNLAFailedToSetupList.
	IdTNLAFailedToSetupList int64 = 357

	// IdUnlicensedSpectrumRestriction is the integer constant for IdUnlicensedSpectrumRestriction.
	IdUnlicensedSpectrumRestriction int64 = 358

	// IdUEContextReferenceatSourceNGRAN is the integer constant for IdUEContextReferenceatSourceNGRAN.
	IdUEContextReferenceatSourceNGRAN int64 = 359

	// IdEPCHandoverRestrictionListContainer is the integer constant for IdEPCHandoverRestrictionListContainer.
	IdEPCHandoverRestrictionListContainer int64 = 360

	// IdCHOinformationREQ is the integer constant for IdCHOinformationREQ.
	IdCHOinformationREQ int64 = 361

	// IdCHOinformationACK is the integer constant for IdCHOinformationACK.
	IdCHOinformationACK int64 = 362

	// IdDAPSRequestInfo is the integer constant for IdDAPSRequestInfo.
	IdDAPSRequestInfo int64 = 363

	// IdRequestedTargetCellID is the integer constant for IdRequestedTargetCellID.
	IdRequestedTargetCellID int64 = 364

	// IdCandidateCellsToBeCancelledList is the integer constant for IdCandidateCellsToBeCancelledList.
	IdCandidateCellsToBeCancelledList int64 = 365

	// IdDAPSResponseInfo is the integer constant for IdDAPSResponseInfo.
	IdDAPSResponseInfo int64 = 366

	// IdProcedureStage is the integer constant for IdProcedureStage.
	IdProcedureStage int64 = 367

	// IdCHODCIndicator is the integer constant for IdCHODCIndicator.
	IdCHODCIndicator int64 = 368

	// IdEthernetType is the integer constant for IdEthernetType.
	IdEthernetType int64 = 369

	// IdNRV2XServicesAuthorized is the integer constant for IdNRV2XServicesAuthorized.
	IdNRV2XServicesAuthorized int64 = 370

	// IdNRUESidelinkAggregateMaximumBitRate is the integer constant for IdNRUESidelinkAggregateMaximumBitRate.
	IdNRUESidelinkAggregateMaximumBitRate int64 = 371

	// IdPC5QoSParameters is the integer constant for IdPC5QoSParameters.
	IdPC5QoSParameters int64 = 372

	// IdNPRACHConfiguration is the integer constant for IdNPRACHConfiguration.
	IdNPRACHConfiguration int64 = 373

	// IdNBIoTRLFReportContainer is the integer constant for IdNBIoTRLFReportContainer.
	IdNBIoTRLFReportContainer int64 = 374

	// IdMDTConfigurationNR is the integer constant for IdMDTConfigurationNR.
	IdMDTConfigurationNR int64 = 375

	// IdPrivacyIndicator is the integer constant for IdPrivacyIndicator.
	IdPrivacyIndicator int64 = 376

	// IdTraceCollectionEntityIPAddress is the integer constant for IdTraceCollectionEntityIPAddress.
	IdTraceCollectionEntityIPAddress int64 = 377

	// IdUERadioCapabilityID is the integer constant for IdUERadioCapabilityID.
	IdUERadioCapabilityID int64 = 378

	// IdSNtriggered is the integer constant for IdSNtriggered.
	IdSNtriggered int64 = 379

	// IdCSIRSTransmissionIndication is the integer constant for IdCSIRSTransmissionIndication.
	IdCSIRSTransmissionIndication int64 = 380

	// IdDLCarrierList is the integer constant for IdDLCarrierList.
	IdDLCarrierList int64 = 381

	// IdTargetCellInNGRAN is the integer constant for IdTargetCellInNGRAN.
	IdTargetCellInNGRAN int64 = 382

	// IdEUTRANNode1MeasurementID is the integer constant for IdEUTRANNode1MeasurementID.
	IdEUTRANNode1MeasurementID int64 = 383

	// IdEUTRANNode2MeasurementID is the integer constant for IdEUTRANNode2MeasurementID.
	IdEUTRANNode2MeasurementID int64 = 384

	// IdTDDULDLConfigurationCommonNR is the integer constant for IdTDDULDLConfigurationCommonNR.
	IdTDDULDLConfigurationCommonNR int64 = 385

	// IdCarrierList is the integer constant for IdCarrierList.
	IdCarrierList int64 = 386

	// IdULCarrierList is the integer constant for IdULCarrierList.
	IdULCarrierList int64 = 387

	// IdFrequencyShift7p5khz is the integer constant for IdFrequencyShift7p5khz.
	IdFrequencyShift7p5khz int64 = 388

	// IdSSBPositionsInBurst is the integer constant for IdSSBPositionsInBurst.
	IdSSBPositionsInBurst int64 = 389

	// IdNRCellPRACHConfig is the integer constant for IdNRCellPRACHConfig.
	IdNRCellPRACHConfig int64 = 390

	// IdCellToReportNRENDC is the integer constant for IdCellToReportNRENDC.
	IdCellToReportNRENDC int64 = 391

	// IdCellToReportNRENDCItem is the integer constant for IdCellToReportNRENDCItem.
	IdCellToReportNRENDCItem int64 = 392

	// IdCellMeasurementResultNRENDC is the integer constant for IdCellMeasurementResultNRENDC.
	IdCellMeasurementResultNRENDC int64 = 393

	// IdCellMeasurementResultNRENDCItem is the integer constant for IdCellMeasurementResultNRENDCItem.
	IdCellMeasurementResultNRENDCItem int64 = 394

	// IdIABNodeIndication is the integer constant for IdIABNodeIndication.
	IdIABNodeIndication int64 = 395

	// IdQoSMappingInformation is the integer constant for IdQoSMappingInformation.
	IdQoSMappingInformation int64 = 396

	// IdF1CTrafficContainer is the integer constant for IdF1CTrafficContainer.
	IdF1CTrafficContainer int64 = 397

	// IdUnknown398 is the integer constant for IdUnknown398.
	IdUnknown398 int64 = 398

	// IdIntendedTDDDLULConfigurationNR is the integer constant for IdIntendedTDDDLULConfigurationNR.
	IdIntendedTDDDLULConfigurationNR int64 = 399

	// IdUERadioCapability is the integer constant for IdUERadioCapability.
	IdUERadioCapability int64 = 400

	// IdCellMeasurementResultEUTRAENDC is the integer constant for IdCellMeasurementResultEUTRAENDC.
	IdCellMeasurementResultEUTRAENDC int64 = 401

	// IdCellMeasurementResultEUTRAENDCItem is the integer constant for IdCellMeasurementResultEUTRAENDCItem.
	IdCellMeasurementResultEUTRAENDCItem int64 = 402

	// IdCellToReportEUTRAENDC is the integer constant for IdCellToReportEUTRAENDC.
	IdCellToReportEUTRAENDC int64 = 403

	// IdCellToReportEUTRAENDCItem is the integer constant for IdCellToReportEUTRAENDCItem.
	IdCellToReportEUTRAENDCItem int64 = 404

	// IdTraceCollectionEntityURI is the integer constant for IdTraceCollectionEntityURI.
	IdTraceCollectionEntityURI int64 = 405

	// IdSFNOffset is the integer constant for IdSFNOffset.
	IdSFNOffset int64 = 406

	// IdCHODCEarlyDataForwarding is the integer constant for IdCHODCEarlyDataForwarding.
	IdCHODCEarlyDataForwarding int64 = 407

	// IdIMSvoiceEPSfallbackfrom5G is the integer constant for IdIMSvoiceEPSfallbackfrom5G.
	IdIMSvoiceEPSfallbackfrom5G int64 = 408

	// IdAdditionLocationInformation is the integer constant for IdAdditionLocationInformation.
	IdAdditionLocationInformation int64 = 409

	// IdDirectForwardingPathAvailability is the integer constant for IdDirectForwardingPathAvailability.
	IdDirectForwardingPathAvailability int64 = 410

	// IdSourceNGRANNodeId is the integer constant for IdSourceNGRANNodeId.
	IdSourceNGRANNodeId int64 = 411

	// IdSourceDLForwardingIPAddress is the integer constant for IdSourceDLForwardingIPAddress.
	IdSourceDLForwardingIPAddress int64 = 412

	// IdSourceNodeDLForwardingIPAddress is the integer constant for IdSourceNodeDLForwardingIPAddress.
	IdSourceNodeDLForwardingIPAddress int64 = 413

	// IdNRRAReport is the integer constant for IdNRRAReport.
	IdNRRAReport int64 = 414

	// IdSCGUEHistoryInformation is the integer constant for IdSCGUEHistoryInformation.
	IdSCGUEHistoryInformation int64 = 415

	// IdPSCellHistoryInformationRetrieve is the integer constant for IdPSCellHistoryInformationRetrieve.
	IdPSCellHistoryInformationRetrieve int64 = 416

	// IdMeasurementResultforNRCellsPossiblyAggregated is the integer constant for IdMeasurementResultforNRCellsPossiblyAggregated.
	IdMeasurementResultforNRCellsPossiblyAggregated int64 = 417

	// IdPSCellUEHistoryInformation is the integer constant for IdPSCellUEHistoryInformation.
	IdPSCellUEHistoryInformation int64 = 418

	// IdPSCellChangeHistory is the integer constant for IdPSCellChangeHistory.
	IdPSCellChangeHistory int64 = 419

	// IdCHOinformationAddReq is the integer constant for IdCHOinformationAddReq.
	IdCHOinformationAddReq int64 = 420

	// IdCHOinformationModReq is the integer constant for IdCHOinformationModReq.
	IdCHOinformationModReq int64 = 421

	// IdSCGActivationStatus is the integer constant for IdSCGActivationStatus.
	IdSCGActivationStatus int64 = 422

	// IdSCGActivationRequest is the integer constant for IdSCGActivationRequest.
	IdSCGActivationRequest int64 = 423

	// IdCPAinformationREQ is the integer constant for IdCPAinformationREQ.
	IdCPAinformationREQ int64 = 424

	// IdCPAinformationREQACK is the integer constant for IdCPAinformationREQACK.
	IdCPAinformationREQACK int64 = 425

	// IdCPAinformationMOD is the integer constant for IdCPAinformationMOD.
	IdCPAinformationMOD int64 = 426

	// IdCPAinformationMODACK is the integer constant for IdCPAinformationMODACK.
	IdCPAinformationMODACK int64 = 427

	// IdCPACinformationREQD is the integer constant for IdCPACinformationREQD.
	IdCPACinformationREQD int64 = 428

	// IdCPCinformationREQD is the integer constant for IdCPCinformationREQD.
	IdCPCinformationREQD int64 = 429

	// IdCPCinformationCONF is the integer constant for IdCPCinformationCONF.
	IdCPCinformationCONF int64 = 430

	// IdCPCinformationNOTIFY is the integer constant for IdCPCinformationNOTIFY.
	IdCPCinformationNOTIFY int64 = 431

	// IdCPCupdateMOD is the integer constant for IdCPCupdateMOD.
	IdCPCupdateMOD int64 = 432

	// IdAdditionalMeasurementTimingConfigurationList is the integer constant for IdAdditionalMeasurementTimingConfigurationList.
	IdAdditionalMeasurementTimingConfigurationList int64 = 433

	// IdServedCellSpecificInfoReqNR is the integer constant for IdServedCellSpecificInfoReqNR.
	IdServedCellSpecificInfoReqNR int64 = 434

	// IdSecurityIndication is the integer constant for IdSecurityIndication.
	IdSecurityIndication int64 = 435

	// IdSecurityResult is the integer constant for IdSecurityResult.
	IdSecurityResult int64 = 436

	// IdRATRestrictions is the integer constant for IdRATRestrictions.
	IdRATRestrictions int64 = 437

	// IdSCGreconfigNotification is the integer constant for IdSCGreconfigNotification.
	IdSCGreconfigNotification int64 = 438

	// IdMIMOPRBusageInformation is the integer constant for IdMIMOPRBusageInformation.
	IdMIMOPRBusageInformation int64 = 439

	// IdSensorMeasurementConfiguration is the integer constant for IdSensorMeasurementConfiguration.
	IdSensorMeasurementConfiguration int64 = 440

	// IdAdditionalListofForwardingGTPTunnelEndpoint is the integer constant for IdAdditionalListofForwardingGTPTunnelEndpoint.
	IdAdditionalListofForwardingGTPTunnelEndpoint int64 = 441

	// IdM4ReportAmount is the integer constant for IdM4ReportAmount.
	IdM4ReportAmount int64 = 442

	// IdM5ReportAmount is the integer constant for IdM5ReportAmount.
	IdM5ReportAmount int64 = 443

	// IdM6ReportAmount is the integer constant for IdM6ReportAmount.
	IdM6ReportAmount int64 = 444

	// IdM7ReportAmount is the integer constant for IdM7ReportAmount.
	IdM7ReportAmount int64 = 445

	// IdCHOTimeBasedInformation is the integer constant for IdCHOTimeBasedInformation.
	IdCHOTimeBasedInformation int64 = 446

	// IdRaReportIndicationList is the integer constant for IdRaReportIndicationList.
	IdRaReportIndicationList int64 = 447

	// IdPSCellListContainer is the integer constant for IdPSCellListContainer.
	IdPSCellListContainer int64 = 448

	// IdIABAuthorized is the integer constant for IdIABAuthorized.
	IdIABAuthorized int64 = 449

	// IdSourcePSCellCGI is the integer constant for IdSourcePSCellCGI.
	IdSourcePSCellCGI int64 = 450

	// IdFailedPSCellCGI is the integer constant for IdFailedPSCellCGI.
	IdFailedPSCellCGI int64 = 451

	// IdSCGFailureReportContainer is the integer constant for IdSCGFailureReportContainer.
	IdSCGFailureReportContainer int64 = 452

	// IdTimeSCGFailure is the integer constant for IdTimeSCGFailure.
	IdTimeSCGFailure int64 = 453
)
