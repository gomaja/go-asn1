// Code generated from ASN.1 module "LPPA-Constants". DO NOT EDIT.

package lppa

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

	// IdErrorIndication is the integer constant for id-errorIndication.
	IdErrorIndication int64 = 0

	// IdPrivateMessage is the integer constant for id-privateMessage.
	IdPrivateMessage int64 = 1

	// IdECIDMeasurementInitiation is the integer constant for id-e-CIDMeasurementInitiation.
	IdECIDMeasurementInitiation int64 = 2

	// IdECIDMeasurementFailureIndication is the integer constant for id-e-CIDMeasurementFailureIndication.
	IdECIDMeasurementFailureIndication int64 = 3

	// IdECIDMeasurementReport is the integer constant for id-e-CIDMeasurementReport.
	IdECIDMeasurementReport int64 = 4

	// IdECIDMeasurementTermination is the integer constant for id-e-CIDMeasurementTermination.
	IdECIDMeasurementTermination int64 = 5

	// IdOTDOAInformationExchange is the integer constant for id-oTDOAInformationExchange.
	IdOTDOAInformationExchange int64 = 6

	// IdUTDOAInformationExchange is the integer constant for id-uTDOAInformationExchange.
	IdUTDOAInformationExchange int64 = 7

	// IdUTDOAInformationUpdate is the integer constant for id-uTDOAInformationUpdate.
	IdUTDOAInformationUpdate int64 = 8

	// IdAssistanceInformationControl is the integer constant for id-assistanceInformationControl.
	IdAssistanceInformationControl int64 = 9

	// IdAssistanceInformationFeedback is the integer constant for id-assistanceInformationFeedback.
	IdAssistanceInformationFeedback int64 = 10

	// MaxNrOfErrors is the integer constant for maxNrOfErrors.
	MaxNrOfErrors int64 = 256

	// MaxCellineNB is the integer constant for maxCellineNB.
	MaxCellineNB int64 = 256

	// MaxNoMeas is the integer constant for maxNoMeas.
	MaxNoMeas int64 = 63

	// MaxCellReport is the integer constant for maxCellReport.
	MaxCellReport int64 = 9

	// MaxnoOTDOAtypes is the integer constant for maxnoOTDOAtypes.
	MaxnoOTDOAtypes int64 = 63

	// MaxServCell is the integer constant for maxServCell.
	MaxServCell int64 = 5

	// MaxGERANMeas is the integer constant for maxGERANMeas.
	MaxGERANMeas int64 = 8

	// MaxUTRANMeas is the integer constant for maxUTRANMeas.
	MaxUTRANMeas int64 = 8

	// MaxCellineNBExt is the integer constant for maxCellineNB-ext.
	MaxCellineNBExt int64 = 3840

	// MaxMBSFNAllocations is the integer constant for maxMBSFN-Allocations.
	MaxMBSFNAllocations int64 = 8

	// MaxWLANchannels is the integer constant for maxWLANchannels.
	MaxWLANchannels int64 = 16

	// MaxnoFreqHoppingBandsMinusOne is the integer constant for maxnoFreqHoppingBandsMinusOne.
	MaxnoFreqHoppingBandsMinusOne int64 = 7

	// MaxNrOfPosSImessage is the integer constant for maxNrOfPosSImessage.
	MaxNrOfPosSImessage int64 = 32

	// MaxnoAssistInfoFailureListItems is the integer constant for maxnoAssistInfoFailureListItems.
	MaxnoAssistInfoFailureListItems int64 = 32

	// MaxNrOfSegments is the integer constant for maxNrOfSegments.
	MaxNrOfSegments int64 = 64

	// MaxNrOfPosSIBs is the integer constant for maxNrOfPosSIBs.
	MaxNrOfPosSIBs int64 = 32

	// MaxNRmeas is the integer constant for maxNRmeas.
	MaxNRmeas int64 = 32

	// MaxResultsPerSSBIndex is the integer constant for maxResultsPerSSBIndex.
	MaxResultsPerSSBIndex int64 = 64

	// IdCause is the integer constant for id-Cause.
	IdCause int64 = 0

	// IdCriticalityDiagnostics is the integer constant for id-CriticalityDiagnostics.
	IdCriticalityDiagnostics int64 = 1

	// IdESMLCUEMeasurementID is the integer constant for id-E-SMLC-UE-Measurement-ID.
	IdESMLCUEMeasurementID int64 = 2

	// IdReportCharacteristics is the integer constant for id-ReportCharacteristics.
	IdReportCharacteristics int64 = 3

	// IdMeasurementPeriodicity is the integer constant for id-MeasurementPeriodicity.
	IdMeasurementPeriodicity int64 = 4

	// IdMeasurementQuantities is the integer constant for id-MeasurementQuantities.
	IdMeasurementQuantities int64 = 5

	// IdENBUEMeasurementID is the integer constant for id-eNB-UE-Measurement-ID.
	IdENBUEMeasurementID int64 = 6

	// IdECIDMeasurementResult is the integer constant for id-E-CID-MeasurementResult.
	IdECIDMeasurementResult int64 = 7

	// IdOTDOACells is the integer constant for id-OTDOACells.
	IdOTDOACells int64 = 8

	// IdOTDOAInformationTypeGroup is the integer constant for id-OTDOA-Information-Type-Group.
	IdOTDOAInformationTypeGroup int64 = 9

	// IdOTDOAInformationTypeItem is the integer constant for id-OTDOA-Information-Type-Item.
	IdOTDOAInformationTypeItem int64 = 10

	// IdMeasurementQuantitiesItem is the integer constant for id-MeasurementQuantities-Item.
	IdMeasurementQuantitiesItem int64 = 11

	// IdRequestedSRSTransmissionCharacteristics is the integer constant for id-RequestedSRSTransmissionCharacteristics.
	IdRequestedSRSTransmissionCharacteristics int64 = 12

	// IdULConfiguration is the integer constant for id-ULConfiguration.
	IdULConfiguration int64 = 13

	// IdCellPortionID is the integer constant for id-Cell-Portion-ID.
	IdCellPortionID int64 = 14

	// IdInterRATMeasurementQuantities is the integer constant for id-InterRATMeasurementQuantities.
	IdInterRATMeasurementQuantities int64 = 15

	// IdInterRATMeasurementQuantitiesItem is the integer constant for id-InterRATMeasurementQuantities-Item.
	IdInterRATMeasurementQuantitiesItem int64 = 16

	// IdInterRATMeasurementResult is the integer constant for id-InterRATMeasurementResult.
	IdInterRATMeasurementResult int64 = 17

	// IdAddOTDOACells is the integer constant for id-AddOTDOACells.
	IdAddOTDOACells int64 = 18

	// IdWLANMeasurementQuantities is the integer constant for id-WLANMeasurementQuantities.
	IdWLANMeasurementQuantities int64 = 19

	// IdWLANMeasurementQuantitiesItem is the integer constant for id-WLANMeasurementQuantities-Item.
	IdWLANMeasurementQuantitiesItem int64 = 20

	// IdWLANMeasurementResult is the integer constant for id-WLANMeasurementResult.
	IdWLANMeasurementResult int64 = 21

	// IdAssistanceInformation is the integer constant for id-Assistance-Information.
	IdAssistanceInformation int64 = 22

	// IdBroadcast is the integer constant for id-Broadcast.
	IdBroadcast int64 = 23

	// IdAssistanceInformationFailureList is the integer constant for id-AssistanceInformationFailureList.
	IdAssistanceInformationFailureList int64 = 24

	// IdResultsPerSSBIndexList is the integer constant for id-ResultsPerSSB-Index-List.
	IdResultsPerSSBIndexList int64 = 25

	// IdResultsPerSSBIndexItem is the integer constant for id-ResultsPerSSB-Index-Item.
	IdResultsPerSSBIndexItem int64 = 26

	// IdNRCGI is the integer constant for id-NR-CGI.
	IdNRCGI int64 = 27
)
