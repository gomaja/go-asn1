// Code generated from ASN.1. DO NOT EDIT.

package s1ap

import (
	"fmt"
	"reflect"

	"github.com/gomaja/go-asn1/runtime/per"
)

// DecodeInitiatingMessageValue decodes the Value field of InitiatingMessage based on procedureCode.
// Returns the decoded typed struct, or nil if the procedureCode is unknown.
func DecodeInitiatingMessageValue(procedureCode int64, data []byte) (interface{}, error) {
	bb := per.NewBitBufferFromBytes(data)
	switch procedureCode {
	case 0: // id-HandoverPreparation
		var v HandoverRequired
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverRequired: %w", err)
		}
		return &v, nil
	case 1: // id-HandoverResourceAllocation
		var v HandoverRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverRequest: %w", err)
		}
		return &v, nil
	case 2: // id-HandoverNotification
		var v HandoverNotify
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverNotify: %w", err)
		}
		return &v, nil
	case 3: // id-PathSwitchRequest
		var v PathSwitchRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding PathSwitchRequest: %w", err)
		}
		return &v, nil
	case 5: // id-E-RABSetup
		var v ERABSetupRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ERABSetupRequest: %w", err)
		}
		return &v, nil
	case 6: // id-E-RABModify
		var v ERABModifyRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ERABModifyRequest: %w", err)
		}
		return &v, nil
	case 7: // id-E-RABRelease
		var v ERABReleaseCommand
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ERABReleaseCommand: %w", err)
		}
		return &v, nil
	case 8: // id-E-RABReleaseIndication
		var v ERABReleaseIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ERABReleaseIndication: %w", err)
		}
		return &v, nil
	case 9: // id-InitialContextSetup
		var v InitialContextSetupRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding InitialContextSetupRequest: %w", err)
		}
		return &v, nil
	case 18: // id-UEContextReleaseRequest
		var v UEContextReleaseRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UEContextReleaseRequest: %w", err)
		}
		return &v, nil
	case 10: // id-Paging
		var v Paging
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding Paging: %w", err)
		}
		return &v, nil
	case 11: // id-downlinkNASTransport
		var v DownlinkNASTransport
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding DownlinkNASTransport: %w", err)
		}
		return &v, nil
	case 12: // id-initialUEMessage
		var v InitialUEMessage
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding InitialUEMessage: %w", err)
		}
		return &v, nil
	case 13: // id-uplinkNASTransport
		var v UplinkNASTransport
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UplinkNASTransport: %w", err)
		}
		return &v, nil
	case 16: // id-NASNonDeliveryIndication
		var v NASNonDeliveryIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding NASNonDeliveryIndication: %w", err)
		}
		return &v, nil
	case 4: // id-HandoverCancel
		var v HandoverCancel
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverCancel: %w", err)
		}
		return &v, nil
	case 14: // id-Reset
		var v Reset
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding Reset: %w", err)
		}
		return &v, nil
	case 15: // id-ErrorIndication
		var v ErrorIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ErrorIndication: %w", err)
		}
		return &v, nil
	case 17: // id-S1Setup
		var v S1SetupRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding S1SetupRequest: %w", err)
		}
		return &v, nil
	case 29: // id-ENBConfigurationUpdate
		var v ENBConfigurationUpdate
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENBConfigurationUpdate: %w", err)
		}
		return &v, nil
	case 30: // id-MMEConfigurationUpdate
		var v MMEConfigurationUpdate
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding MMEConfigurationUpdate: %w", err)
		}
		return &v, nil
	case 19: // id-DownlinkS1cdma2000tunnelling
		var v DownlinkS1cdma2000tunnelling
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding DownlinkS1cdma2000tunnelling: %w", err)
		}
		return &v, nil
	case 20: // id-UplinkS1cdma2000tunnelling
		var v UplinkS1cdma2000tunnelling
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UplinkS1cdma2000tunnelling: %w", err)
		}
		return &v, nil
	case 21: // id-UEContextModification
		var v UEContextModificationRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UEContextModificationRequest: %w", err)
		}
		return &v, nil
	case 22: // id-UECapabilityInfoIndication
		var v UECapabilityInfoIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UECapabilityInfoIndication: %w", err)
		}
		return &v, nil
	case 23: // id-UEContextRelease
		var v UEContextReleaseCommand
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UEContextReleaseCommand: %w", err)
		}
		return &v, nil
	case 24: // id-eNBStatusTransfer
		var v ENBStatusTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENBStatusTransfer: %w", err)
		}
		return &v, nil
	case 25: // id-MMEStatusTransfer
		var v MMEStatusTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding MMEStatusTransfer: %w", err)
		}
		return &v, nil
	case 26: // id-DeactivateTrace
		var v DeactivateTrace
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding DeactivateTrace: %w", err)
		}
		return &v, nil
	case 27: // id-TraceStart
		var v TraceStart
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding TraceStart: %w", err)
		}
		return &v, nil
	case 28: // id-TraceFailureIndication
		var v TraceFailureIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding TraceFailureIndication: %w", err)
		}
		return &v, nil
	case 42: // id-CellTrafficTrace
		var v CellTrafficTrace
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding CellTrafficTrace: %w", err)
		}
		return &v, nil
	case 31: // id-LocationReportingControl
		var v LocationReportingControl
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding LocationReportingControl: %w", err)
		}
		return &v, nil
	case 32: // id-LocationReportingFailureIndication
		var v LocationReportingFailureIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding LocationReportingFailureIndication: %w", err)
		}
		return &v, nil
	case 33: // id-LocationReport
		var v LocationReport
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding LocationReport: %w", err)
		}
		return &v, nil
	case 34: // id-OverloadStart
		var v OverloadStart
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding OverloadStart: %w", err)
		}
		return &v, nil
	case 35: // id-OverloadStop
		var v OverloadStop
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding OverloadStop: %w", err)
		}
		return &v, nil
	case 36: // id-WriteReplaceWarning
		var v WriteReplaceWarningRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding WriteReplaceWarningRequest: %w", err)
		}
		return &v, nil
	case 37: // id-eNBDirectInformationTransfer
		var v ENBDirectInformationTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENBDirectInformationTransfer: %w", err)
		}
		return &v, nil
	case 38: // id-MMEDirectInformationTransfer
		var v MMEDirectInformationTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding MMEDirectInformationTransfer: %w", err)
		}
		return &v, nil
	case 40: // id-eNBConfigurationTransfer
		var v ENBConfigurationTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENBConfigurationTransfer: %w", err)
		}
		return &v, nil
	case 41: // id-MMEConfigurationTransfer
		var v MMEConfigurationTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding MMEConfigurationTransfer: %w", err)
		}
		return &v, nil
	case 39: // id-PrivateMessage
		var v PrivateMessage
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding PrivateMessage: %w", err)
		}
		return &v, nil
	case 49: // id-PWSRestartIndication
		var v PWSRestartIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding PWSRestartIndication: %w", err)
		}
		return &v, nil
	case 43: // id-Kill
		var v KillRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding KillRequest: %w", err)
		}
		return &v, nil
	case 44: // id-downlinkUEAssociatedLPPaTransport
		var v DownlinkUEAssociatedLPPaTransport
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding DownlinkUEAssociatedLPPaTransport: %w", err)
		}
		return &v, nil
	case 45: // id-uplinkUEAssociatedLPPaTransport
		var v UplinkUEAssociatedLPPaTransport
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UplinkUEAssociatedLPPaTransport: %w", err)
		}
		return &v, nil
	case 46: // id-downlinkNonUEAssociatedLPPaTransport
		var v DownlinkNonUEAssociatedLPPaTransport
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding DownlinkNonUEAssociatedLPPaTransport: %w", err)
		}
		return &v, nil
	case 47: // id-uplinkNonUEAssociatedLPPaTransport
		var v UplinkNonUEAssociatedLPPaTransport
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UplinkNonUEAssociatedLPPaTransport: %w", err)
		}
		return &v, nil
	case 48: // id-UERadioCapabilityMatch
		var v UERadioCapabilityMatchRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UERadioCapabilityMatchRequest: %w", err)
		}
		return &v, nil
	case 50: // id-E-RABModificationIndication
		var v ERABModificationIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ERABModificationIndication: %w", err)
		}
		return &v, nil
	case 53: // id-UEContextModificationIndication
		var v UEContextModificationIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UEContextModificationIndication: %w", err)
		}
		return &v, nil
	case 52: // id-RerouteNASRequest
		var v RerouteNASRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding RerouteNASRequest: %w", err)
		}
		return &v, nil
	case 51: // id-PWSFailureIndication
		var v PWSFailureIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding PWSFailureIndication: %w", err)
		}
		return &v, nil
	case 55: // id-UEContextSuspend
		var v UEContextSuspendRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UEContextSuspendRequest: %w", err)
		}
		return &v, nil
	case 56: // id-UEContextResume
		var v UEContextResumeRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UEContextResumeRequest: %w", err)
		}
		return &v, nil
	case 54: // id-ConnectionEstablishmentIndication
		var v ConnectionEstablishmentIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ConnectionEstablishmentIndication: %w", err)
		}
		return &v, nil
	case 57: // id-NASDeliveryIndication
		var v NASDeliveryIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding NASDeliveryIndication: %w", err)
		}
		return &v, nil
	case 58: // id-RetrieveUEInformation
		var v RetrieveUEInformation
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding RetrieveUEInformation: %w", err)
		}
		return &v, nil
	case 59: // id-UEInformationTransfer
		var v UEInformationTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UEInformationTransfer: %w", err)
		}
		return &v, nil
	case 60: // id-eNBCPRelocationIndication
		var v ENBCPRelocationIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENBCPRelocationIndication: %w", err)
		}
		return &v, nil
	case 61: // id-MMECPRelocationIndication
		var v MMECPRelocationIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding MMECPRelocationIndication: %w", err)
		}
		return &v, nil
	case 62: // id-SecondaryRATDataUsageReport
		var v SecondaryRATDataUsageReport
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SecondaryRATDataUsageReport: %w", err)
		}
		return &v, nil
	case 63: // id-UERadioCapabilityIDMapping
		var v UERadioCapabilityIDMappingRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UERadioCapabilityIDMappingRequest: %w", err)
		}
		return &v, nil
	case 64: // id-HandoverSuccess
		var v HandoverSuccess
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverSuccess: %w", err)
		}
		return &v, nil
	case 65: // id-eNBEarlyStatusTransfer
		var v ENBEarlyStatusTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENBEarlyStatusTransfer: %w", err)
		}
		return &v, nil
	case 66: // id-MMEEarlyStatusTransfer
		var v MMEEarlyStatusTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding MMEEarlyStatusTransfer: %w", err)
		}
		return &v, nil
	default:
		return nil, nil
	}
}

// DecodeSuccessfulOutcomeValue decodes the Value field of SuccessfulOutcome based on procedureCode.
// Returns the decoded typed struct, or nil if the procedureCode is unknown.
func DecodeSuccessfulOutcomeValue(procedureCode int64, data []byte) (interface{}, error) {
	bb := per.NewBitBufferFromBytes(data)
	switch procedureCode {
	case 0: // id-HandoverPreparation
		var v HandoverCommand
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverCommand: %w", err)
		}
		return &v, nil
	case 1: // id-HandoverResourceAllocation
		var v HandoverRequestAcknowledge
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverRequestAcknowledge: %w", err)
		}
		return &v, nil
	case 3: // id-PathSwitchRequest
		var v PathSwitchRequestAcknowledge
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding PathSwitchRequestAcknowledge: %w", err)
		}
		return &v, nil
	case 5: // id-E-RABSetup
		var v ERABSetupResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ERABSetupResponse: %w", err)
		}
		return &v, nil
	case 6: // id-E-RABModify
		var v ERABModifyResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ERABModifyResponse: %w", err)
		}
		return &v, nil
	case 7: // id-E-RABRelease
		var v ERABReleaseResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ERABReleaseResponse: %w", err)
		}
		return &v, nil
	case 9: // id-InitialContextSetup
		var v InitialContextSetupResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding InitialContextSetupResponse: %w", err)
		}
		return &v, nil
	case 4: // id-HandoverCancel
		var v HandoverCancelAcknowledge
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverCancelAcknowledge: %w", err)
		}
		return &v, nil
	case 14: // id-Reset
		var v ResetAcknowledge
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ResetAcknowledge: %w", err)
		}
		return &v, nil
	case 17: // id-S1Setup
		var v S1SetupResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding S1SetupResponse: %w", err)
		}
		return &v, nil
	case 29: // id-ENBConfigurationUpdate
		var v ENBConfigurationUpdateAcknowledge
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENBConfigurationUpdateAcknowledge: %w", err)
		}
		return &v, nil
	case 30: // id-MMEConfigurationUpdate
		var v MMEConfigurationUpdateAcknowledge
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding MMEConfigurationUpdateAcknowledge: %w", err)
		}
		return &v, nil
	case 21: // id-UEContextModification
		var v UEContextModificationResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UEContextModificationResponse: %w", err)
		}
		return &v, nil
	case 23: // id-UEContextRelease
		var v UEContextReleaseComplete
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UEContextReleaseComplete: %w", err)
		}
		return &v, nil
	case 36: // id-WriteReplaceWarning
		var v WriteReplaceWarningResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding WriteReplaceWarningResponse: %w", err)
		}
		return &v, nil
	case 43: // id-Kill
		var v KillResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding KillResponse: %w", err)
		}
		return &v, nil
	case 48: // id-UERadioCapabilityMatch
		var v UERadioCapabilityMatchResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UERadioCapabilityMatchResponse: %w", err)
		}
		return &v, nil
	case 50: // id-E-RABModificationIndication
		var v ERABModificationConfirm
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ERABModificationConfirm: %w", err)
		}
		return &v, nil
	case 53: // id-UEContextModificationIndication
		var v UEContextModificationConfirm
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UEContextModificationConfirm: %w", err)
		}
		return &v, nil
	case 55: // id-UEContextSuspend
		var v UEContextSuspendResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UEContextSuspendResponse: %w", err)
		}
		return &v, nil
	case 56: // id-UEContextResume
		var v UEContextResumeResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UEContextResumeResponse: %w", err)
		}
		return &v, nil
	case 63: // id-UERadioCapabilityIDMapping
		var v UERadioCapabilityIDMappingResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UERadioCapabilityIDMappingResponse: %w", err)
		}
		return &v, nil
	default:
		return nil, nil
	}
}

// DecodeUnsuccessfulOutcomeValue decodes the Value field of UnsuccessfulOutcome based on procedureCode.
// Returns the decoded typed struct, or nil if the procedureCode is unknown.
func DecodeUnsuccessfulOutcomeValue(procedureCode int64, data []byte) (interface{}, error) {
	bb := per.NewBitBufferFromBytes(data)
	switch procedureCode {
	case 0: // id-HandoverPreparation
		var v HandoverPreparationFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverPreparationFailure: %w", err)
		}
		return &v, nil
	case 1: // id-HandoverResourceAllocation
		var v HandoverFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverFailure: %w", err)
		}
		return &v, nil
	case 3: // id-PathSwitchRequest
		var v PathSwitchRequestFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding PathSwitchRequestFailure: %w", err)
		}
		return &v, nil
	case 9: // id-InitialContextSetup
		var v InitialContextSetupFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding InitialContextSetupFailure: %w", err)
		}
		return &v, nil
	case 17: // id-S1Setup
		var v S1SetupFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding S1SetupFailure: %w", err)
		}
		return &v, nil
	case 29: // id-ENBConfigurationUpdate
		var v ENBConfigurationUpdateFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENBConfigurationUpdateFailure: %w", err)
		}
		return &v, nil
	case 30: // id-MMEConfigurationUpdate
		var v MMEConfigurationUpdateFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding MMEConfigurationUpdateFailure: %w", err)
		}
		return &v, nil
	case 21: // id-UEContextModification
		var v UEContextModificationFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UEContextModificationFailure: %w", err)
		}
		return &v, nil
	case 56: // id-UEContextResume
		var v UEContextResumeFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UEContextResumeFailure: %w", err)
		}
		return &v, nil
	default:
		return nil, nil
	}
}

// decodeIEProtocolIEFieldListConstrained decodes a constrained SEQUENCE OF ProtocolIEField values from APER.
// with the given SIZE constraint bounds.
func decodeIEProtocolIEFieldListConstrained(bb *per.BitBuffer, lb, ub int64) ([]ProtocolIEField, error) {
	n, err := per.DecodeConstrainedWholeNumberAligned(bb, lb, ub)
	if err != nil {
		return nil, fmt.Errorf("decoding list length: %w", err)
	}
	result := make([]ProtocolIEField, n)
	for i := int64(0); i < n; i++ {
		if err := result[i].UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding item %d: %w", i, err)
		}
	}
	return result, nil
}

// DecodeIEFieldValue decodes a known IE open value using its object-set context and ID.
// Returns the decoded typed value, or nil if the combination is unknown.
func DecodeIEFieldValue(messageType string, ieId int64, data []byte) (interface{}, error) {
	bb := per.NewBitBufferFromBytes(data)
	switch messageType {
	case "BearersSubjectToStatusTransferItem", "Bearers-SubjectToStatusTransfer-ItemIEs":
		switch ieId {
		case 89: // id-Bearers-SubjectToStatusTransfer-Item -> Bearers-SubjectToStatusTransfer-Item
			var v BearersSubjectToStatusTransferItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Bearers-SubjectToStatusTransfer-Item (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "BearersSubjectToEarlyStatusTransferItem", "Bearers-SubjectToEarlyStatusTransfer-ItemIEs":
		switch ieId {
		case 322: // id-Bearers-SubjectToEarlyStatusTransfer-Item -> Bearers-SubjectToEarlyStatusTransfer-Item
			var v BearersSubjectToEarlyStatusTransferItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Bearers-SubjectToEarlyStatusTransfer-Item (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "DAPSResponseInfoList", "DAPSResponseInfoListIEs":
		switch ieId {
		case 319: // id-DAPSResponseInfoItem -> DAPSResponseInfoItem
			var v DAPSResponseInfoItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE DAPSResponseInfoItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABInformationList", "E-RABInformationListIEs":
		switch ieId {
		case 78: // id-E-RABInformationListItem -> E-RABInformationListItem
			var v ERABInformationListItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE E-RABInformationListItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABItem", "E-RABItemIEs":
		switch ieId {
		case 35: // id-E-RABItem -> E-RABItem
			var v ERABItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE E-RABItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABSecurityResultList", "E-RABSecurityResultListIEs":
		switch ieId {
		case 334: // id-E-RABSecurityResultItem -> E-RABSecurityResultItem
			var v ERABSecurityResultItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE E-RABSecurityResultItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABUsageReportItem", "E-RABUsageReportItemIEs":
		switch ieId {
		case 267: // id-E-RABUsageReportItem -> E-RABUsageReportItem
			var v ERABUsageReportItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE E-RABUsageReportItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MDTModeExtensionIE", "MDTMode-ExtensionIE":
		switch ieId {
		case 197: // id-LoggedMBSFNMDT -> LoggedMBSFNMDT
			var v LoggedMBSFNMDT
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LoggedMBSFNMDT (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "RecommendedCellItem", "RecommendedCellItemIEs":
		switch ieId {
		case 214: // id-RecommendedCellItem -> RecommendedCellItem
			var v RecommendedCellItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RecommendedCellItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "RecommendedENBItem", "RecommendedENBItemIEs":
		switch ieId {
		case 215: // id-RecommendedENBItem -> RecommendedENBItem
			var v RecommendedENBItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RecommendedENBItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SecondaryRATDataUsageReportItem", "SecondaryRATDataUsageReportItemIEs":
		switch ieId {
		case 265: // id-SecondaryRATDataUsageReportItem -> SecondaryRATDataUsageReportItem
			var v SecondaryRATDataUsageReportItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SecondaryRATDataUsageReportItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SONInformationExtensionIE", "SONInformation-ExtensionIE":
		switch ieId {
		case 206: // id-SON-Information-Report -> SONInformationReport
			var v SONInformationReport
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SONInformationReport (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverRequired", "HandoverRequiredIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 1: // id-HandoverType -> HandoverType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 5, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE HandoverType (%d): %w", ieId, err)
			}
			result := HandoverType(v)
			return &result, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 4: // id-TargetID -> TargetID
			var v TargetID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TargetID (%d): %w", ieId, err)
			}
			return &v, nil
		case 79: // id-Direct-Forwarding-Path-Availability -> Direct-Forwarding-Path-Availability (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Direct-Forwarding-Path-Availability (%d): %w", ieId, err)
			}
			result := DirectForwardingPathAvailability(v)
			return &result, nil
		case 125: // id-SRVCCHOIndication -> SRVCCHOIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SRVCCHOIndication (%d): %w", ieId, err)
			}
			result := SRVCCHOIndication(v)
			return &result, nil
		case 104: // id-Source-ToTarget-TransparentContainer -> Source-ToTarget-TransparentContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Source-ToTarget-TransparentContainer (%d): %w", ieId, err)
			}
			result := SourceToTargetTransparentContainer(v)
			return &result, nil
		case 138: // id-Source-ToTarget-TransparentContainer-Secondary -> Source-ToTarget-TransparentContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Source-ToTarget-TransparentContainer (%d): %w", ieId, err)
			}
			result := SourceToTargetTransparentContainer(v)
			return &result, nil
		case 132: // id-MSClassmark2 -> MSClassmark2 (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MSClassmark2 (%d): %w", ieId, err)
			}
			result := MSClassmark2(v)
			return &result, nil
		case 133: // id-MSClassmark3 -> MSClassmark3 (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MSClassmark3 (%d): %w", ieId, err)
			}
			result := MSClassmark3(v)
			return &result, nil
		case 127: // id-CSG-Id -> CSG-Id (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 27, 27, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSG-Id (%d): %w", ieId, err)
			}
			result := CSGId{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 145: // id-CellAccessMode -> CellAccessMode (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellAccessMode (%d): %w", ieId, err)
			}
			result := CellAccessMode(v)
			return &result, nil
		case 150: // id-PS-ServiceNotAvailable -> PS-ServiceNotAvailable (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PS-ServiceNotAvailable (%d): %w", ieId, err)
			}
			result := PSServiceNotAvailable(v)
			return &result, nil
		}
	case "HandoverCommand", "HandoverCommandIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 1: // id-HandoverType -> HandoverType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 5, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE HandoverType (%d): %w", ieId, err)
			}
			result := HandoverType(v)
			return &result, nil
		case 135: // id-NASSecurityParametersfromE-UTRAN -> NASSecurityParametersfromE-UTRAN (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NASSecurityParametersfromE-UTRAN (%d): %w", ieId, err)
			}
			result := NASSecurityParametersfromEUTRAN(v)
			return &result, nil
		case 12: // id-E-RABSubjecttoDataForwardingList -> ERABSubjecttoDataForwardingList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABSubjecttoDataForwardingList (%d): %w", ieId, err)
			}
			return &v, nil
		case 13: // id-E-RABtoReleaseListHOCmd -> E-RABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 123: // id-Target-ToSource-TransparentContainer -> Target-ToSource-TransparentContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Target-ToSource-TransparentContainer (%d): %w", ieId, err)
			}
			result := TargetToSourceTransparentContainer(v)
			return &result, nil
		case 139: // id-Target-ToSource-TransparentContainer-Secondary -> Target-ToSource-TransparentContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Target-ToSource-TransparentContainer (%d): %w", ieId, err)
			}
			result := TargetToSourceTransparentContainer(v)
			return &result, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABDataForwardingItem", "E-RABDataForwardingItemIEs":
		switch ieId {
		case 14: // id-E-RABDataForwardingItem -> ERABDataForwardingItem
			var v ERABDataForwardingItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABDataForwardingItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverPreparationFailure", "HandoverPreparationFailureIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverRequest", "HandoverRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 1: // id-HandoverType -> HandoverType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 5, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE HandoverType (%d): %w", ieId, err)
			}
			result := HandoverType(v)
			return &result, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 66: // id-uEaggregateMaximumBitrate -> UEAggregateMaximumBitrate
			var v UEAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 53: // id-E-RABToBeSetupListHOReq -> ERABToBeSetupListHOReq (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSetupListHOReq (%d): %w", ieId, err)
			}
			return &v, nil
		case 104: // id-Source-ToTarget-TransparentContainer -> Source-ToTarget-TransparentContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Source-ToTarget-TransparentContainer (%d): %w", ieId, err)
			}
			result := SourceToTargetTransparentContainer(v)
			return &result, nil
		case 107: // id-UESecurityCapabilities -> UESecurityCapabilities
			var v UESecurityCapabilities
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UESecurityCapabilities (%d): %w", ieId, err)
			}
			return &v, nil
		case 41: // id-HandoverRestrictionList -> HandoverRestrictionList
			var v HandoverRestrictionList
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE HandoverRestrictionList (%d): %w", ieId, err)
			}
			return &v, nil
		case 25: // id-TraceActivation -> TraceActivation
			var v TraceActivation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TraceActivation (%d): %w", ieId, err)
			}
			return &v, nil
		case 98: // id-RequestType -> RequestType
			var v RequestType
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RequestType (%d): %w", ieId, err)
			}
			return &v, nil
		case 124: // id-SRVCCOperationPossible -> SRVCCOperationPossible (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SRVCCOperationPossible (%d): %w", ieId, err)
			}
			result := SRVCCOperationPossible(v)
			return &result, nil
		case 40: // id-SecurityContext -> SecurityContext
			var v SecurityContext
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SecurityContext (%d): %w", ieId, err)
			}
			return &v, nil
		case 136: // id-NASSecurityParameterstoE-UTRAN -> NASSecurityParameterstoE-UTRAN (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NASSecurityParameterstoE-UTRAN (%d): %w", ieId, err)
			}
			result := NASSecurityParameterstoEUTRAN(v)
			return &result, nil
		case 127: // id-CSG-Id -> CSG-Id (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 27, 27, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSG-Id (%d): %w", ieId, err)
			}
			result := CSGId{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 146: // id-CSGMembershipStatus -> CSGMembershipStatus (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGMembershipStatus (%d): %w", ieId, err)
			}
			result := CSGMembershipStatus(v)
			return &result, nil
		case 75: // id-GUMMEI-ID -> GUMMEI
			var v GUMMEI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GUMMEI (%d): %w", ieId, err)
			}
			return &v, nil
		case 158: // id-MME-UE-S1AP-ID-2 -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 165: // id-ManagementBasedMDTAllowed -> ManagementBasedMDTAllowed (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ManagementBasedMDTAllowed (%d): %w", ieId, err)
			}
			result := ManagementBasedMDTAllowed(v)
			return &result, nil
		case 192: // id-Masked-IMEISV -> Masked-IMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Masked-IMEISV (%d): %w", ieId, err)
			}
			result := MaskedIMEISV{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 196: // id-ExpectedUEBehaviour -> ExpectedUEBehaviour
			var v ExpectedUEBehaviour
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ExpectedUEBehaviour (%d): %w", ieId, err)
			}
			return &v, nil
		case 195: // id-ProSeAuthorized -> ProSeAuthorized
			var v ProSeAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ProSeAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 241: // id-UEUserPlaneCIoTSupportIndicator -> UEUserPlaneCIoTSupportIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEUserPlaneCIoTSupportIndicator (%d): %w", ieId, err)
			}
			result := UEUserPlaneCIoTSupportIndicator(v)
			return &result, nil
		case 240: // id-V2XServicesAuthorized -> V2XServicesAuthorized
			var v V2XServicesAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE V2XServicesAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 248: // id-UESidelinkAggregateMaximumBitrate -> UESidelinkAggregateMaximumBitrate
			var v UESidelinkAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UESidelinkAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 251: // id-EnhancedCoverageRestricted -> EnhancedCoverageRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EnhancedCoverageRestricted (%d): %w", ieId, err)
			}
			result := EnhancedCoverageRestricted(v)
			return &result, nil
		case 269: // id-NRUESecurityCapabilities -> NRUESecurityCapabilities
			var v NRUESecurityCapabilities
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRUESecurityCapabilities (%d): %w", ieId, err)
			}
			return &v, nil
		case 271: // id-CE-ModeBRestricted -> CE-ModeBRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CE-ModeBRestricted (%d): %w", ieId, err)
			}
			result := CEModeBRestricted(v)
			return &result, nil
		case 277: // id-AerialUEsubscriptionInformation -> AerialUEsubscriptionInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AerialUEsubscriptionInformation (%d): %w", ieId, err)
			}
			result := AerialUEsubscriptionInformation(v)
			return &result, nil
		case 283: // id-PendingDataIndication -> PendingDataIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PendingDataIndication (%d): %w", ieId, err)
			}
			result := PendingDataIndication(v)
			return &result, nil
		case 278: // id-Subscription-Based-UE-DifferentiationInfo -> Subscription-Based-UE-DifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Subscription-Based-UE-DifferentiationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 299: // id-AdditionalRRMPriorityIndex -> AdditionalRRMPriorityIndex (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AdditionalRRMPriorityIndex (%d): %w", ieId, err)
			}
			result := AdditionalRRMPriorityIndex{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 301: // id-IAB-Authorized -> IAB-Authorized (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IAB-Authorized (%d): %w", ieId, err)
			}
			result := IABAuthorized(v)
			return &result, nil
		case 306: // id-NRV2XServicesAuthorized -> NRV2XServicesAuthorized
			var v NRV2XServicesAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRV2XServicesAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 307: // id-NRUESidelinkAggregateMaximumBitrate -> NRUESidelinkAggregateMaximumBitrate
			var v NRUESidelinkAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRUESidelinkAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 308: // id-PC5QoSParameters -> PC5QoSParameters
			var v PC5QoSParameters
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE PC5QoSParameters (%d): %w", ieId, err)
			}
			return &v, nil
		case 314: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityID (%d): %w", ieId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		}
	case "ERABToBeSetupItemHOReq", "E-RABToBeSetupItemHOReqIEs":
		switch ieId {
		case 27: // id-E-RABToBeSetupItemHOReq -> ERABToBeSetupItemHOReq
			var v ERABToBeSetupItemHOReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSetupItemHOReq (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverRequestAcknowledge", "HandoverRequestAcknowledgeIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 18: // id-E-RABAdmittedList -> ERABAdmittedList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABAdmittedList (%d): %w", ieId, err)
			}
			return &v, nil
		case 19: // id-E-RABFailedToSetupListHOReqAck -> ERABFailedtoSetupListHOReqAck (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABFailedtoSetupListHOReqAck (%d): %w", ieId, err)
			}
			return &v, nil
		case 123: // id-Target-ToSource-TransparentContainer -> Target-ToSource-TransparentContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Target-ToSource-TransparentContainer (%d): %w", ieId, err)
			}
			result := TargetToSourceTransparentContainer(v)
			return &result, nil
		case 127: // id-CSG-Id -> CSG-Id (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 27, 27, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSG-Id (%d): %w", ieId, err)
			}
			result := CSGId{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 145: // id-CellAccessMode -> CellAccessMode (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellAccessMode (%d): %w", ieId, err)
			}
			result := CellAccessMode(v)
			return &result, nil
		case 242: // id-CE-mode-B-SupportIndicator -> CE-mode-B-SupportIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CE-mode-B-SupportIndicator (%d): %w", ieId, err)
			}
			result := CEModeBSupportIndicator(v)
			return &result, nil
		}
	case "ERABAdmittedItem", "E-RABAdmittedItemIEs":
		switch ieId {
		case 20: // id-E-RABAdmittedItem -> ERABAdmittedItem
			var v ERABAdmittedItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABAdmittedItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABFailedtoSetupItemHOReqAck", "E-RABFailedtoSetupItemHOReqAckIEs":
		switch ieId {
		case 21: // id-E-RABFailedtoSetupItemHOReqAck -> ERABFailedToSetupItemHOReqAck
			var v ERABFailedToSetupItemHOReqAck
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABFailedToSetupItemHOReqAck (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverFailure", "HandoverFailureIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverNotify", "HandoverNotifyIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 100: // id-EUTRAN-CGI -> EUTRAN-CGI
			var v EUTRANCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EUTRAN-CGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 67: // id-TAI -> TAI
			var v TAI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TAI (%d): %w", ieId, err)
			}
			return &v, nil
		case 176: // id-Tunnel-Information-for-BBF -> TunnelInformation
			var v TunnelInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TunnelInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 186: // id-LHN-ID -> LHN-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 32, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LHN-ID (%d): %w", ieId, err)
			}
			result := LHNID(v)
			return &result, nil
		case 288: // id-PSCellInformation -> PSCellInformation
			var v PSCellInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE PSCellInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 320: // id-NotifySourceeNB -> NotifySourceeNB (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NotifySourceeNB (%d): %w", ieId, err)
			}
			result := NotifySourceeNB(v)
			return &result, nil
		case 339: // id-LTE-NTN-TAI-Information -> LTE-NTN-TAI-Information
			var v LTENTNTAIInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LTE-NTN-TAI-Information (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "PathSwitchRequest", "PathSwitchRequestIEs":
		switch ieId {
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 22: // id-E-RABToBeSwitchedDLList -> ERABToBeSwitchedDLList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSwitchedDLList (%d): %w", ieId, err)
			}
			return &v, nil
		case 88: // id-SourceMME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 100: // id-EUTRAN-CGI -> EUTRAN-CGI
			var v EUTRANCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EUTRAN-CGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 67: // id-TAI -> TAI
			var v TAI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TAI (%d): %w", ieId, err)
			}
			return &v, nil
		case 107: // id-UESecurityCapabilities -> UESecurityCapabilities
			var v UESecurityCapabilities
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UESecurityCapabilities (%d): %w", ieId, err)
			}
			return &v, nil
		case 127: // id-CSG-Id -> CSG-Id (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 27, 27, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSG-Id (%d): %w", ieId, err)
			}
			result := CSGId{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 145: // id-CellAccessMode -> CellAccessMode (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellAccessMode (%d): %w", ieId, err)
			}
			result := CellAccessMode(v)
			return &result, nil
		case 157: // id-SourceMME-GUMMEI -> GUMMEI
			var v GUMMEI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GUMMEI (%d): %w", ieId, err)
			}
			return &v, nil
		case 146: // id-CSGMembershipStatus -> CSGMembershipStatus (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGMembershipStatus (%d): %w", ieId, err)
			}
			result := CSGMembershipStatus(v)
			return &result, nil
		case 176: // id-Tunnel-Information-for-BBF -> TunnelInformation
			var v TunnelInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TunnelInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 186: // id-LHN-ID -> LHN-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 32, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LHN-ID (%d): %w", ieId, err)
			}
			result := LHNID(v)
			return &result, nil
		case 245: // id-RRC-Resume-Cause -> RRC-Establishment-Cause (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 5, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RRC-Establishment-Cause (%d): %w", ieId, err)
			}
			result := RRCEstablishmentCause(v)
			return &result, nil
		case 269: // id-NRUESecurityCapabilities -> NRUESecurityCapabilities
			var v NRUESecurityCapabilities
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRUESecurityCapabilities (%d): %w", ieId, err)
			}
			return &v, nil
		case 288: // id-PSCellInformation -> PSCellInformation
			var v PSCellInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE PSCellInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 339: // id-LTE-NTN-TAI-Information -> LTE-NTN-TAI-Information
			var v LTENTNTAIInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LTE-NTN-TAI-Information (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABToBeSwitchedDLItem", "E-RABToBeSwitchedDLItemIEs":
		switch ieId {
		case 23: // id-E-RABToBeSwitchedDLItem -> ERABToBeSwitchedDLItem
			var v ERABToBeSwitchedDLItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSwitchedDLItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "PathSwitchRequestAcknowledge", "PathSwitchRequestAcknowledgeIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 66: // id-uEaggregateMaximumBitrate -> UEAggregateMaximumBitrate
			var v UEAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 95: // id-E-RABToBeSwitchedULList -> ERABToBeSwitchedULList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSwitchedULList (%d): %w", ieId, err)
			}
			return &v, nil
		case 33: // id-E-RABToBeReleasedList -> E-RABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 40: // id-SecurityContext -> SecurityContext
			var v SecurityContext
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SecurityContext (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 158: // id-MME-UE-S1AP-ID-2 -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 146: // id-CSGMembershipStatus -> CSGMembershipStatus (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGMembershipStatus (%d): %w", ieId, err)
			}
			result := CSGMembershipStatus(v)
			return &result, nil
		case 195: // id-ProSeAuthorized -> ProSeAuthorized
			var v ProSeAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ProSeAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 241: // id-UEUserPlaneCIoTSupportIndicator -> UEUserPlaneCIoTSupportIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEUserPlaneCIoTSupportIndicator (%d): %w", ieId, err)
			}
			result := UEUserPlaneCIoTSupportIndicator(v)
			return &result, nil
		case 240: // id-V2XServicesAuthorized -> V2XServicesAuthorized
			var v V2XServicesAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE V2XServicesAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 248: // id-UESidelinkAggregateMaximumBitrate -> UESidelinkAggregateMaximumBitrate
			var v UESidelinkAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UESidelinkAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 251: // id-EnhancedCoverageRestricted -> EnhancedCoverageRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EnhancedCoverageRestricted (%d): %w", ieId, err)
			}
			result := EnhancedCoverageRestricted(v)
			return &result, nil
		case 269: // id-NRUESecurityCapabilities -> NRUESecurityCapabilities
			var v NRUESecurityCapabilities
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRUESecurityCapabilities (%d): %w", ieId, err)
			}
			return &v, nil
		case 271: // id-CE-ModeBRestricted -> CE-ModeBRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CE-ModeBRestricted (%d): %w", ieId, err)
			}
			result := CEModeBRestricted(v)
			return &result, nil
		case 277: // id-AerialUEsubscriptionInformation -> AerialUEsubscriptionInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AerialUEsubscriptionInformation (%d): %w", ieId, err)
			}
			result := AerialUEsubscriptionInformation(v)
			return &result, nil
		case 283: // id-PendingDataIndication -> PendingDataIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PendingDataIndication (%d): %w", ieId, err)
			}
			result := PendingDataIndication(v)
			return &result, nil
		case 278: // id-Subscription-Based-UE-DifferentiationInfo -> Subscription-Based-UE-DifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Subscription-Based-UE-DifferentiationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 41: // id-HandoverRestrictionList -> HandoverRestrictionList
			var v HandoverRestrictionList
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE HandoverRestrictionList (%d): %w", ieId, err)
			}
			return &v, nil
		case 299: // id-AdditionalRRMPriorityIndex -> AdditionalRRMPriorityIndex (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AdditionalRRMPriorityIndex (%d): %w", ieId, err)
			}
			result := AdditionalRRMPriorityIndex{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 306: // id-NRV2XServicesAuthorized -> NRV2XServicesAuthorized
			var v NRV2XServicesAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRV2XServicesAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 307: // id-NRUESidelinkAggregateMaximumBitrate -> NRUESidelinkAggregateMaximumBitrate
			var v NRUESidelinkAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRUESidelinkAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 308: // id-PC5QoSParameters -> PC5QoSParameters
			var v PC5QoSParameters
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE PC5QoSParameters (%d): %w", ieId, err)
			}
			return &v, nil
		case 314: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityID (%d): %w", ieId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		case 107: // id-UESecurityCapabilities -> UESecurityCapabilities
			var v UESecurityCapabilities
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UESecurityCapabilities (%d): %w", ieId, err)
			}
			return &v, nil
		case 341: // id-E-RABToBeUpdatedList -> ERABToBeUpdatedList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeUpdatedList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABToBeSwitchedULItem", "E-RABToBeSwitchedULItemIEs":
		switch ieId {
		case 94: // id-E-RABToBeSwitchedULItem -> ERABToBeSwitchedULItem
			var v ERABToBeSwitchedULItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSwitchedULItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABToBeUpdatedItem", "E-RABToBeUpdatedItemIEs":
		switch ieId {
		case 342: // id-E-RABToBeUpdatedItem -> ERABToBeUpdatedItem
			var v ERABToBeUpdatedItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeUpdatedItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "PathSwitchRequestFailure", "PathSwitchRequestFailureIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverCancel", "HandoverCancelIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverCancelAcknowledge", "HandoverCancelAcknowledgeIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverSuccess", "HandoverSuccessIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		}
	case "ENBEarlyStatusTransfer", "ENBEarlyStatusTransferIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 321: // id-eNB-EarlyStatusTransfer-TransparentContainer -> ENB-EarlyStatusTransfer-TransparentContainer
			var v ENBEarlyStatusTransferTransparentContainer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ENB-EarlyStatusTransfer-TransparentContainer (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MMEEarlyStatusTransfer", "MMEEarlyStatusTransferIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 321: // id-eNB-EarlyStatusTransfer-TransparentContainer -> ENB-EarlyStatusTransfer-TransparentContainer
			var v ENBEarlyStatusTransferTransparentContainer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ENB-EarlyStatusTransfer-TransparentContainer (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABSetupRequest", "E-RABSetupRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 66: // id-uEaggregateMaximumBitrate -> UEAggregateMaximumBitrate
			var v UEAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 16: // id-E-RABToBeSetupListBearerSUReq -> ERABToBeSetupListBearerSUReq (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSetupListBearerSUReq (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABToBeSetupItemBearerSUReq", "E-RABToBeSetupItemBearerSUReqIEs":
		switch ieId {
		case 17: // id-E-RABToBeSetupItemBearerSUReq -> ERABToBeSetupItemBearerSUReq
			var v ERABToBeSetupItemBearerSUReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSetupItemBearerSUReq (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABSetupResponse", "E-RABSetupResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 28: // id-E-RABSetupListBearerSURes -> ERABSetupListBearerSURes (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABSetupListBearerSURes (%d): %w", ieId, err)
			}
			return &v, nil
		case 29: // id-E-RABFailedToSetupListBearerSURes -> E-RABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 189: // id-UserLocationInformation -> UserLocationInformation
			var v UserLocationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UserLocationInformation (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABSetupItemBearerSURes", "E-RABSetupItemBearerSUResIEs":
		switch ieId {
		case 39: // id-E-RABSetupItemBearerSURes -> ERABSetupItemBearerSURes
			var v ERABSetupItemBearerSURes
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABSetupItemBearerSURes (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABModifyRequest", "E-RABModifyRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 66: // id-uEaggregateMaximumBitrate -> UEAggregateMaximumBitrate
			var v UEAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 30: // id-E-RABToBeModifiedListBearerModReq -> ERABToBeModifiedListBearerModReq (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeModifiedListBearerModReq (%d): %w", ieId, err)
			}
			return &v, nil
		case 268: // id-SecondaryRATDataUsageRequest -> SecondaryRATDataUsageRequest (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SecondaryRATDataUsageRequest (%d): %w", ieId, err)
			}
			result := SecondaryRATDataUsageRequest(v)
			return &result, nil
		}
	case "ERABToBeModifiedItemBearerModReq", "E-RABToBeModifiedItemBearerModReqIEs":
		switch ieId {
		case 36: // id-E-RABToBeModifiedItemBearerModReq -> ERABToBeModifiedItemBearerModReq
			var v ERABToBeModifiedItemBearerModReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeModifiedItemBearerModReq (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABModifyResponse", "E-RABModifyResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 31: // id-E-RABModifyListBearerModRes -> ERABModifyListBearerModRes (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABModifyListBearerModRes (%d): %w", ieId, err)
			}
			return &v, nil
		case 32: // id-E-RABFailedToModifyList -> E-RABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 264: // id-SecondaryRATDataUsageReportList -> SecondaryRATDataUsageReportList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SecondaryRATDataUsageReportList (%d): %w", ieId, err)
			}
			return &v, nil
		case 189: // id-UserLocationInformation -> UserLocationInformation
			var v UserLocationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UserLocationInformation (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABModifyItemBearerModRes", "E-RABModifyItemBearerModResIEs":
		switch ieId {
		case 37: // id-E-RABModifyItemBearerModRes -> ERABModifyItemBearerModRes
			var v ERABModifyItemBearerModRes
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABModifyItemBearerModRes (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABReleaseCommand", "E-RABReleaseCommandIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 66: // id-uEaggregateMaximumBitrate -> UEAggregateMaximumBitrate
			var v UEAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 33: // id-E-RABToBeReleasedList -> E-RABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 26: // id-NAS-PDU -> NAS-PDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NAS-PDU (%d): %w", ieId, err)
			}
			result := NASPDU(v)
			return &result, nil
		}
	case "ERABReleaseResponse", "E-RABReleaseResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 69: // id-E-RABReleaseListBearerRelComp -> ERABReleaseListBearerRelComp (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABReleaseListBearerRelComp (%d): %w", ieId, err)
			}
			return &v, nil
		case 34: // id-E-RABFailedToReleaseList -> E-RABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 189: // id-UserLocationInformation -> UserLocationInformation
			var v UserLocationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UserLocationInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 264: // id-SecondaryRATDataUsageReportList -> SecondaryRATDataUsageReportList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SecondaryRATDataUsageReportList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABReleaseItemBearerRelComp", "E-RABReleaseItemBearerRelCompIEs":
		switch ieId {
		case 15: // id-E-RABReleaseItemBearerRelComp -> ERABReleaseItemBearerRelComp
			var v ERABReleaseItemBearerRelComp
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABReleaseItemBearerRelComp (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABReleaseIndication", "E-RABReleaseIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 110: // id-E-RABReleasedList -> E-RABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 189: // id-UserLocationInformation -> UserLocationInformation
			var v UserLocationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UserLocationInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 264: // id-SecondaryRATDataUsageReportList -> SecondaryRATDataUsageReportList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SecondaryRATDataUsageReportList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "InitialContextSetupRequest", "InitialContextSetupRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 66: // id-uEaggregateMaximumBitrate -> UEAggregateMaximumBitrate
			var v UEAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 24: // id-E-RABToBeSetupListCtxtSUReq -> ERABToBeSetupListCtxtSUReq (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSetupListCtxtSUReq (%d): %w", ieId, err)
			}
			return &v, nil
		case 107: // id-UESecurityCapabilities -> UESecurityCapabilities
			var v UESecurityCapabilities
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UESecurityCapabilities (%d): %w", ieId, err)
			}
			return &v, nil
		case 73: // id-SecurityKey -> SecurityKey (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 256, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SecurityKey (%d): %w", ieId, err)
			}
			result := SecurityKey{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 25: // id-TraceActivation -> TraceActivation
			var v TraceActivation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TraceActivation (%d): %w", ieId, err)
			}
			return &v, nil
		case 41: // id-HandoverRestrictionList -> HandoverRestrictionList
			var v HandoverRestrictionList
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE HandoverRestrictionList (%d): %w", ieId, err)
			}
			return &v, nil
		case 74: // id-UERadioCapability -> UERadioCapability (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapability (%d): %w", ieId, err)
			}
			result := UERadioCapability(v)
			return &result, nil
		case 106: // id-SubscriberProfileIDforRFP -> SubscriberProfileIDforRFP (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(256), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SubscriberProfileIDforRFP (%d): %w", ieId, err)
			}
			result := SubscriberProfileIDforRFP(v)
			return &result, nil
		case 108: // id-CSFallbackIndicator -> CSFallbackIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSFallbackIndicator (%d): %w", ieId, err)
			}
			result := CSFallbackIndicator(v)
			return &result, nil
		case 124: // id-SRVCCOperationPossible -> SRVCCOperationPossible (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SRVCCOperationPossible (%d): %w", ieId, err)
			}
			result := SRVCCOperationPossible(v)
			return &result, nil
		case 146: // id-CSGMembershipStatus -> CSGMembershipStatus (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGMembershipStatus (%d): %w", ieId, err)
			}
			result := CSGMembershipStatus(v)
			return &result, nil
		case 159: // id-RegisteredLAI -> LAI
			var v LAI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LAI (%d): %w", ieId, err)
			}
			return &v, nil
		case 75: // id-GUMMEI-ID -> GUMMEI
			var v GUMMEI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GUMMEI (%d): %w", ieId, err)
			}
			return &v, nil
		case 158: // id-MME-UE-S1AP-ID-2 -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 165: // id-ManagementBasedMDTAllowed -> ManagementBasedMDTAllowed (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ManagementBasedMDTAllowed (%d): %w", ieId, err)
			}
			result := ManagementBasedMDTAllowed(v)
			return &result, nil
		case 187: // id-AdditionalCSFallbackIndicator -> AdditionalCSFallbackIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AdditionalCSFallbackIndicator (%d): %w", ieId, err)
			}
			result := AdditionalCSFallbackIndicator(v)
			return &result, nil
		case 192: // id-Masked-IMEISV -> Masked-IMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Masked-IMEISV (%d): %w", ieId, err)
			}
			result := MaskedIMEISV{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 196: // id-ExpectedUEBehaviour -> ExpectedUEBehaviour
			var v ExpectedUEBehaviour
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ExpectedUEBehaviour (%d): %w", ieId, err)
			}
			return &v, nil
		case 195: // id-ProSeAuthorized -> ProSeAuthorized
			var v ProSeAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ProSeAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 241: // id-UEUserPlaneCIoTSupportIndicator -> UEUserPlaneCIoTSupportIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEUserPlaneCIoTSupportIndicator (%d): %w", ieId, err)
			}
			result := UEUserPlaneCIoTSupportIndicator(v)
			return &result, nil
		case 240: // id-V2XServicesAuthorized -> V2XServicesAuthorized
			var v V2XServicesAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE V2XServicesAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 248: // id-UESidelinkAggregateMaximumBitrate -> UESidelinkAggregateMaximumBitrate
			var v UESidelinkAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UESidelinkAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 251: // id-EnhancedCoverageRestricted -> EnhancedCoverageRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EnhancedCoverageRestricted (%d): %w", ieId, err)
			}
			result := EnhancedCoverageRestricted(v)
			return &result, nil
		case 269: // id-NRUESecurityCapabilities -> NRUESecurityCapabilities
			var v NRUESecurityCapabilities
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRUESecurityCapabilities (%d): %w", ieId, err)
			}
			return &v, nil
		case 271: // id-CE-ModeBRestricted -> CE-ModeBRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CE-ModeBRestricted (%d): %w", ieId, err)
			}
			result := CEModeBRestricted(v)
			return &result, nil
		case 277: // id-AerialUEsubscriptionInformation -> AerialUEsubscriptionInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AerialUEsubscriptionInformation (%d): %w", ieId, err)
			}
			result := AerialUEsubscriptionInformation(v)
			return &result, nil
		case 283: // id-PendingDataIndication -> PendingDataIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PendingDataIndication (%d): %w", ieId, err)
			}
			result := PendingDataIndication(v)
			return &result, nil
		case 278: // id-Subscription-Based-UE-DifferentiationInfo -> Subscription-Based-UE-DifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Subscription-Based-UE-DifferentiationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 299: // id-AdditionalRRMPriorityIndex -> AdditionalRRMPriorityIndex (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AdditionalRRMPriorityIndex (%d): %w", ieId, err)
			}
			result := AdditionalRRMPriorityIndex{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 301: // id-IAB-Authorized -> IAB-Authorized (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IAB-Authorized (%d): %w", ieId, err)
			}
			result := IABAuthorized(v)
			return &result, nil
		case 306: // id-NRV2XServicesAuthorized -> NRV2XServicesAuthorized
			var v NRV2XServicesAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRV2XServicesAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 307: // id-NRUESidelinkAggregateMaximumBitrate -> NRUESidelinkAggregateMaximumBitrate
			var v NRUESidelinkAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRUESidelinkAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 308: // id-PC5QoSParameters -> PC5QoSParameters
			var v PC5QoSParameters
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE PC5QoSParameters (%d): %w", ieId, err)
			}
			return &v, nil
		case 314: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityID (%d): %w", ieId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		}
	case "ERABToBeSetupItemCtxtSUReq", "E-RABToBeSetupItemCtxtSUReqIEs":
		switch ieId {
		case 52: // id-E-RABToBeSetupItemCtxtSUReq -> ERABToBeSetupItemCtxtSUReq
			var v ERABToBeSetupItemCtxtSUReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSetupItemCtxtSUReq (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "InitialContextSetupResponse", "InitialContextSetupResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 51: // id-E-RABSetupListCtxtSURes -> ERABSetupListCtxtSURes (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABSetupListCtxtSURes (%d): %w", ieId, err)
			}
			return &v, nil
		case 48: // id-E-RABFailedToSetupListCtxtSURes -> E-RABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABSetupItemCtxtSURes", "E-RABSetupItemCtxtSUResIEs":
		switch ieId {
		case 50: // id-E-RABSetupItemCtxtSURes -> ERABSetupItemCtxtSURes
			var v ERABSetupItemCtxtSURes
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABSetupItemCtxtSURes (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "InitialContextSetupFailure", "InitialContextSetupFailureIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "Paging", "PagingIEs":
		switch ieId {
		case 80: // id-UEIdentityIndexValue -> UEIdentityIndexValue (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 10, 10, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEIdentityIndexValue (%d): %w", ieId, err)
			}
			result := UEIdentityIndexValue{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 43: // id-UEPagingID -> UEPagingID
			var v UEPagingID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEPagingID (%d): %w", ieId, err)
			}
			return &v, nil
		case 44: // id-pagingDRX -> PagingDRX (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PagingDRX (%d): %w", ieId, err)
			}
			result := PagingDRX(v)
			return &result, nil
		case 109: // id-CNDomain -> CNDomain (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CNDomain (%d): %w", ieId, err)
			}
			result := CNDomain(v)
			return &result, nil
		case 46: // id-TAIList -> TAIList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TAIList (%d): %w", ieId, err)
			}
			return &v, nil
		case 128: // id-CSG-IdList -> CSG-IdList (SEQUENCE OF CSGIdListItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSG-IdList length: %w", err)
			}
			result := make(CSGIdList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE CSG-IdList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 151: // id-PagingPriority -> PagingPriority (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PagingPriority (%d): %w", ieId, err)
			}
			result := PagingPriority(v)
			return &result, nil
		case 198: // id-UERadioCapabilityForPaging -> UERadioCapabilityForPaging (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityForPaging (%d): %w", ieId, err)
			}
			result := UERadioCapabilityForPaging(v)
			return &result, nil
		case 211: // id-AssistanceDataForPaging -> AssistanceDataForPaging
			var v AssistanceDataForPaging
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE AssistanceDataForPaging (%d): %w", ieId, err)
			}
			return &v, nil
		case 227: // id-Paging-eDRXInformation -> Paging-eDRXInformation
			var v PagingEDRXInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Paging-eDRXInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 231: // id-extended-UEIdentityIndexValue -> Extended-UEIdentityIndexValue (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 14, 14, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Extended-UEIdentityIndexValue (%d): %w", ieId, err)
			}
			result := ExtendedUEIdentityIndexValue{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 239: // id-NB-IoT-Paging-eDRXInformation -> NB-IoT-Paging-eDRXInformation
			var v NBIoTPagingEDRXInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NB-IoT-Paging-eDRXInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 244: // id-NB-IoT-UEIdentityIndexValue -> NB-IoT-UEIdentityIndexValue (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 12, 12, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NB-IoT-UEIdentityIndexValue (%d): %w", ieId, err)
			}
			result := NBIoTUEIdentityIndexValue{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 251: // id-EnhancedCoverageRestricted -> EnhancedCoverageRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EnhancedCoverageRestricted (%d): %w", ieId, err)
			}
			result := EnhancedCoverageRestricted(v)
			return &result, nil
		case 271: // id-CE-ModeBRestricted -> CE-ModeBRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CE-ModeBRestricted (%d): %w", ieId, err)
			}
			result := CEModeBRestricted(v)
			return &result, nil
		case 304: // id-DataSize -> DataSize (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE DataSize (%d): %w", ieId, err)
			}
			result := DataSize(v)
			return &result, nil
		case 323: // id-WUS-Assistance-Information -> WUS-Assistance-Information
			var v WUSAssistanceInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE WUS-Assistance-Information (%d): %w", ieId, err)
			}
			return &v, nil
		case 324: // id-NB-IoT-PagingDRX -> NB-IoT-PagingDRX (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 6, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NB-IoT-PagingDRX (%d): %w", ieId, err)
			}
			result := NBIoTPagingDRX(v)
			return &result, nil
		case 331: // id-PagingCause -> PagingCause (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PagingCause (%d): %w", ieId, err)
			}
			result := PagingCause(v)
			return &result, nil
		}
	case "TAIItem", "TAIItemIEs":
		switch ieId {
		case 47: // id-TAIItem -> TAIItem
			var v TAIItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TAIItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextReleaseRequest", "UEContextReleaseRequest-IEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 164: // id-GWContextReleaseIndication -> GWContextReleaseIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GWContextReleaseIndication (%d): %w", ieId, err)
			}
			result := GWContextReleaseIndication(v)
			return &result, nil
		case 264: // id-SecondaryRATDataUsageReportList -> SecondaryRATDataUsageReportList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SecondaryRATDataUsageReportList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextReleaseCommand", "UEContextReleaseCommand-IEs":
		switch ieId {
		case 99: // id-UE-S1AP-IDs -> UE-S1AP-IDs
			var v UES1APIDs
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UE-S1AP-IDs (%d): %w", ieId, err)
			}
			return &v, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextReleaseComplete", "UEContextReleaseComplete-IEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 189: // id-UserLocationInformation -> UserLocationInformation
			var v UserLocationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UserLocationInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 213: // id-InformationOnRecommendedCellsAndENBsForPaging -> InformationOnRecommendedCellsAndENBsForPaging
			var v InformationOnRecommendedCellsAndENBsForPaging
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE InformationOnRecommendedCellsAndENBsForPaging (%d): %w", ieId, err)
			}
			return &v, nil
		case 212: // id-CellIdentifierAndCELevelForCECapableUEs -> CellIdentifierAndCELevelForCECapableUEs
			var v CellIdentifierAndCELevelForCECapableUEs
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellIdentifierAndCELevelForCECapableUEs (%d): %w", ieId, err)
			}
			return &v, nil
		case 264: // id-SecondaryRATDataUsageReportList -> SecondaryRATDataUsageReportList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SecondaryRATDataUsageReportList (%d): %w", ieId, err)
			}
			return &v, nil
		case 297: // id-TimeSinceSecondaryNodeRelease -> TimeSinceSecondaryNodeRelease (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeSinceSecondaryNodeRelease (%d): %w", ieId, err)
			}
			result := TimeSinceSecondaryNodeRelease(v)
			return &result, nil
		}
	case "UEContextModificationRequest", "UEContextModificationRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 73: // id-SecurityKey -> SecurityKey (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 256, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SecurityKey (%d): %w", ieId, err)
			}
			result := SecurityKey{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 106: // id-SubscriberProfileIDforRFP -> SubscriberProfileIDforRFP (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(256), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SubscriberProfileIDforRFP (%d): %w", ieId, err)
			}
			result := SubscriberProfileIDforRFP(v)
			return &result, nil
		case 66: // id-uEaggregateMaximumBitrate -> UEAggregateMaximumBitrate
			var v UEAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 108: // id-CSFallbackIndicator -> CSFallbackIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSFallbackIndicator (%d): %w", ieId, err)
			}
			result := CSFallbackIndicator(v)
			return &result, nil
		case 107: // id-UESecurityCapabilities -> UESecurityCapabilities
			var v UESecurityCapabilities
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UESecurityCapabilities (%d): %w", ieId, err)
			}
			return &v, nil
		case 146: // id-CSGMembershipStatus -> CSGMembershipStatus (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGMembershipStatus (%d): %w", ieId, err)
			}
			result := CSGMembershipStatus(v)
			return &result, nil
		case 159: // id-RegisteredLAI -> LAI
			var v LAI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LAI (%d): %w", ieId, err)
			}
			return &v, nil
		case 187: // id-AdditionalCSFallbackIndicator -> AdditionalCSFallbackIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AdditionalCSFallbackIndicator (%d): %w", ieId, err)
			}
			result := AdditionalCSFallbackIndicator(v)
			return &result, nil
		case 195: // id-ProSeAuthorized -> ProSeAuthorized
			var v ProSeAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ProSeAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 124: // id-SRVCCOperationPossible -> SRVCCOperationPossible (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SRVCCOperationPossible (%d): %w", ieId, err)
			}
			result := SRVCCOperationPossible(v)
			return &result, nil
		case 243: // id-SRVCCOperationNotPossible -> SRVCCOperationNotPossible (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SRVCCOperationNotPossible (%d): %w", ieId, err)
			}
			result := SRVCCOperationNotPossible(v)
			return &result, nil
		case 240: // id-V2XServicesAuthorized -> V2XServicesAuthorized
			var v V2XServicesAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE V2XServicesAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 248: // id-UESidelinkAggregateMaximumBitrate -> UESidelinkAggregateMaximumBitrate
			var v UESidelinkAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UESidelinkAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 269: // id-NRUESecurityCapabilities -> NRUESecurityCapabilities
			var v NRUESecurityCapabilities
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRUESecurityCapabilities (%d): %w", ieId, err)
			}
			return &v, nil
		case 277: // id-AerialUEsubscriptionInformation -> AerialUEsubscriptionInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AerialUEsubscriptionInformation (%d): %w", ieId, err)
			}
			result := AerialUEsubscriptionInformation(v)
			return &result, nil
		case 299: // id-AdditionalRRMPriorityIndex -> AdditionalRRMPriorityIndex (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AdditionalRRMPriorityIndex (%d): %w", ieId, err)
			}
			result := AdditionalRRMPriorityIndex{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 301: // id-IAB-Authorized -> IAB-Authorized (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IAB-Authorized (%d): %w", ieId, err)
			}
			result := IABAuthorized(v)
			return &result, nil
		case 306: // id-NRV2XServicesAuthorized -> NRV2XServicesAuthorized
			var v NRV2XServicesAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRV2XServicesAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 307: // id-NRUESidelinkAggregateMaximumBitrate -> NRUESidelinkAggregateMaximumBitrate
			var v NRUESidelinkAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRUESidelinkAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 308: // id-PC5QoSParameters -> PC5QoSParameters
			var v PC5QoSParameters
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE PC5QoSParameters (%d): %w", ieId, err)
			}
			return &v, nil
		case 314: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityID (%d): %w", ieId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		}
	case "UEContextModificationResponse", "UEContextModificationResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextModificationFailure", "UEContextModificationFailureIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UERadioCapabilityMatchRequest", "UERadioCapabilityMatchRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 74: // id-UERadioCapability -> UERadioCapability (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapability (%d): %w", ieId, err)
			}
			result := UERadioCapability(v)
			return &result, nil
		case 314: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityID (%d): %w", ieId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		}
	case "UERadioCapabilityMatchResponse", "UERadioCapabilityMatchResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 169: // id-VoiceSupportMatchIndicator -> VoiceSupportMatchIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE VoiceSupportMatchIndicator (%d): %w", ieId, err)
			}
			result := VoiceSupportMatchIndicator(v)
			return &result, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "DownlinkNASTransport", "DownlinkNASTransport-IEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 26: // id-NAS-PDU -> NAS-PDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NAS-PDU (%d): %w", ieId, err)
			}
			result := NASPDU(v)
			return &result, nil
		case 41: // id-HandoverRestrictionList -> HandoverRestrictionList
			var v HandoverRestrictionList
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE HandoverRestrictionList (%d): %w", ieId, err)
			}
			return &v, nil
		case 106: // id-SubscriberProfileIDforRFP -> SubscriberProfileIDforRFP (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(256), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SubscriberProfileIDforRFP (%d): %w", ieId, err)
			}
			result := SubscriberProfileIDforRFP(v)
			return &result, nil
		case 124: // id-SRVCCOperationPossible -> SRVCCOperationPossible (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SRVCCOperationPossible (%d): %w", ieId, err)
			}
			result := SRVCCOperationPossible(v)
			return &result, nil
		case 74: // id-UERadioCapability -> UERadioCapability (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapability (%d): %w", ieId, err)
			}
			result := UERadioCapability(v)
			return &result, nil
		case 249: // id-DLNASPDUDeliveryAckRequest -> DLNASPDUDeliveryAckRequest (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE DLNASPDUDeliveryAckRequest (%d): %w", ieId, err)
			}
			result := DLNASPDUDeliveryAckRequest(v)
			return &result, nil
		case 251: // id-EnhancedCoverageRestricted -> EnhancedCoverageRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EnhancedCoverageRestricted (%d): %w", ieId, err)
			}
			result := EnhancedCoverageRestricted(v)
			return &result, nil
		case 269: // id-NRUESecurityCapabilities -> NRUESecurityCapabilities
			var v NRUESecurityCapabilities
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRUESecurityCapabilities (%d): %w", ieId, err)
			}
			return &v, nil
		case 271: // id-CE-ModeBRestricted -> CE-ModeBRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CE-ModeBRestricted (%d): %w", ieId, err)
			}
			result := CEModeBRestricted(v)
			return &result, nil
		case 275: // id-UECapabilityInfoRequest -> UECapabilityInfoRequest (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UECapabilityInfoRequest (%d): %w", ieId, err)
			}
			result := UECapabilityInfoRequest(v)
			return &result, nil
		case 280: // id-EndIndication -> EndIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EndIndication (%d): %w", ieId, err)
			}
			result := EndIndication(v)
			return &result, nil
		case 283: // id-PendingDataIndication -> PendingDataIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PendingDataIndication (%d): %w", ieId, err)
			}
			result := PendingDataIndication(v)
			return &result, nil
		case 278: // id-Subscription-Based-UE-DifferentiationInfo -> Subscription-Based-UE-DifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Subscription-Based-UE-DifferentiationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 299: // id-AdditionalRRMPriorityIndex -> AdditionalRRMPriorityIndex (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AdditionalRRMPriorityIndex (%d): %w", ieId, err)
			}
			result := AdditionalRRMPriorityIndex{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 314: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityID (%d): %w", ieId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		case 192: // id-Masked-IMEISV -> Masked-IMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Masked-IMEISV (%d): %w", ieId, err)
			}
			result := MaskedIMEISV{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "InitialUEMessage", "InitialUEMessage-IEs":
		switch ieId {
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 26: // id-NAS-PDU -> NAS-PDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NAS-PDU (%d): %w", ieId, err)
			}
			result := NASPDU(v)
			return &result, nil
		case 67: // id-TAI -> TAI
			var v TAI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TAI (%d): %w", ieId, err)
			}
			return &v, nil
		case 100: // id-EUTRAN-CGI -> EUTRAN-CGI
			var v EUTRANCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EUTRAN-CGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 134: // id-RRC-Establishment-Cause -> RRC-Establishment-Cause (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 5, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RRC-Establishment-Cause (%d): %w", ieId, err)
			}
			result := RRCEstablishmentCause(v)
			return &result, nil
		case 96: // id-S-TMSI -> S-TMSI
			var v STMSI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE S-TMSI (%d): %w", ieId, err)
			}
			return &v, nil
		case 127: // id-CSG-Id -> CSG-Id (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 27, 27, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSG-Id (%d): %w", ieId, err)
			}
			result := CSGId{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 75: // id-GUMMEI-ID -> GUMMEI
			var v GUMMEI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GUMMEI (%d): %w", ieId, err)
			}
			return &v, nil
		case 145: // id-CellAccessMode -> CellAccessMode (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellAccessMode (%d): %w", ieId, err)
			}
			result := CellAccessMode(v)
			return &result, nil
		case 155: // id-GW-TransportLayerAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TransportLayerAddress (%d): %w", ieId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 160: // id-RelayNode-Indicator -> RelayNode-Indicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RelayNode-Indicator (%d): %w", ieId, err)
			}
			result := RelayNodeIndicator(v)
			return &result, nil
		case 170: // id-GUMMEIType -> GUMMEIType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GUMMEIType (%d): %w", ieId, err)
			}
			result := GUMMEIType(v)
			return &result, nil
		case 176: // id-Tunnel-Information-for-BBF -> TunnelInformation
			var v TunnelInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TunnelInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 184: // id-SIPTO-L-GW-TransportLayerAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TransportLayerAddress (%d): %w", ieId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 186: // id-LHN-ID -> LHN-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 32, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LHN-ID (%d): %w", ieId, err)
			}
			result := LHNID(v)
			return &result, nil
		case 223: // id-MME-Group-ID -> MME-Group-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 2, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-Group-ID (%d): %w", ieId, err)
			}
			result := MMEGroupID(v)
			return &result, nil
		case 230: // id-UE-Usage-Type -> UE-Usage-Type (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-Usage-Type (%d): %w", ieId, err)
			}
			result := UEUsageType(v)
			return &result, nil
		case 242: // id-CE-mode-B-SupportIndicator -> CE-mode-B-SupportIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CE-mode-B-SupportIndicator (%d): %w", ieId, err)
			}
			result := CEModeBSupportIndicator(v)
			return &result, nil
		case 246: // id-DCN-ID -> DCN-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(65535), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE DCN-ID (%d): %w", ieId, err)
			}
			result := DCNID(v)
			return &result, nil
		case 250: // id-Coverage-Level -> Coverage-Level (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Coverage-Level (%d): %w", ieId, err)
			}
			result := CoverageLevel(v)
			return &result, nil
		case 263: // id-UE-Application-Layer-Measurement-Capability -> UE-Application-Layer-Measurement-Capability (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-Application-Layer-Measurement-Capability (%d): %w", ieId, err)
			}
			result := UEApplicationLayerMeasurementCapability{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 281: // id-EDT-Session -> EDT-Session (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EDT-Session (%d): %w", ieId, err)
			}
			result := EDTSession(v)
			return &result, nil
		case 302: // id-IAB-Node-Indication -> IAB-Node-Indication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IAB-Node-Indication (%d): %w", ieId, err)
			}
			result := IABNodeIndication(v)
			return &result, nil
		case 339: // id-LTE-NTN-TAI-Information -> LTE-NTN-TAI-Information
			var v LTENTNTAIInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LTE-NTN-TAI-Information (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UplinkNASTransport", "UplinkNASTransport-IEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 26: // id-NAS-PDU -> NAS-PDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NAS-PDU (%d): %w", ieId, err)
			}
			result := NASPDU(v)
			return &result, nil
		case 100: // id-EUTRAN-CGI -> EUTRAN-CGI
			var v EUTRANCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EUTRAN-CGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 67: // id-TAI -> TAI
			var v TAI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TAI (%d): %w", ieId, err)
			}
			return &v, nil
		case 155: // id-GW-TransportLayerAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TransportLayerAddress (%d): %w", ieId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 184: // id-SIPTO-L-GW-TransportLayerAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TransportLayerAddress (%d): %w", ieId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 186: // id-LHN-ID -> LHN-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 32, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LHN-ID (%d): %w", ieId, err)
			}
			result := LHNID(v)
			return &result, nil
		case 288: // id-PSCellInformation -> PSCellInformation
			var v PSCellInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE PSCellInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 339: // id-LTE-NTN-TAI-Information -> LTE-NTN-TAI-Information
			var v LTENTNTAIInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LTE-NTN-TAI-Information (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "NASNonDeliveryIndication", "NASNonDeliveryIndication-IEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 26: // id-NAS-PDU -> NAS-PDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NAS-PDU (%d): %w", ieId, err)
			}
			result := NASPDU(v)
			return &result, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "RerouteNASRequest", "RerouteNASRequest-IEs":
		switch ieId {
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 223: // id-MME-Group-ID -> MME-Group-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 2, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-Group-ID (%d): %w", ieId, err)
			}
			result := MMEGroupID(v)
			return &result, nil
		case 224: // id-Additional-GUTI -> Additional-GUTI
			var v AdditionalGUTI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Additional-GUTI (%d): %w", ieId, err)
			}
			return &v, nil
		case 230: // id-UE-Usage-Type -> UE-Usage-Type (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-Usage-Type (%d): %w", ieId, err)
			}
			result := UEUsageType(v)
			return &result, nil
		}
	case "NASDeliveryIndication", "NASDeliveryIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		}
	case "Reset", "ResetIEs":
		switch ieId {
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 92: // id-ResetType -> ResetType
			var v ResetType
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ResetType (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEAssociatedLogicalS1ConnectionItemRes", "UE-associatedLogicalS1-ConnectionItemRes":
		switch ieId {
		case 91: // id-UE-associatedLogicalS1-ConnectionItem -> UE-associatedLogicalS1-ConnectionItem
			var v UEAssociatedLogicalS1ConnectionItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UE-associatedLogicalS1-ConnectionItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ResetAcknowledge", "ResetAcknowledgeIEs":
		switch ieId {
		case 93: // id-UE-associatedLogicalS1-ConnectionListResAck -> UEAssociatedLogicalS1ConnectionListResAck (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEAssociatedLogicalS1ConnectionListResAck (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEAssociatedLogicalS1ConnectionItemResAck", "UE-associatedLogicalS1-ConnectionItemResAck":
		switch ieId {
		case 91: // id-UE-associatedLogicalS1-ConnectionItem -> UE-associatedLogicalS1-ConnectionItem
			var v UEAssociatedLogicalS1ConnectionItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UE-associatedLogicalS1-ConnectionItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ErrorIndication", "ErrorIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 96: // id-S-TMSI -> S-TMSI
			var v STMSI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE S-TMSI (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "S1SetupRequest", "S1SetupRequestIEs":
		switch ieId {
		case 59: // id-Global-ENB-ID -> Global-ENB-ID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Global-ENB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		case 64: // id-SupportedTAs -> SupportedTAs (SEQUENCE OF SupportedTAsItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SupportedTAs length: %w", err)
			}
			result := make(SupportedTAs, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE SupportedTAs item %d: %w", i, err)
				}
			}
			return &result, nil
		case 137: // id-DefaultPagingDRX -> PagingDRX (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PagingDRX (%d): %w", ieId, err)
			}
			result := PagingDRX(v)
			return &result, nil
		case 128: // id-CSG-IdList -> CSG-IdList (SEQUENCE OF CSGIdListItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSG-IdList length: %w", err)
			}
			result := make(CSGIdList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE CSG-IdList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 228: // id-UE-RetentionInformation -> UE-RetentionInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-RetentionInformation (%d): %w", ieId, err)
			}
			result := UERetentionInformation(v)
			return &result, nil
		case 234: // id-NB-IoT-DefaultPagingDRX -> NB-IoT-DefaultPagingDRX (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NB-IoT-DefaultPagingDRX (%d): %w", ieId, err)
			}
			result := NBIoTDefaultPagingDRX(v)
			return &result, nil
		case 291: // id-ConnectedengNBList -> ConnectedengNBList (SEQUENCE OF ConnectedengNBItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ConnectedengNBList length: %w", err)
			}
			result := make(ConnectedengNBList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ConnectedengNBList item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "S1SetupResponse", "S1SetupResponseIEs":
		switch ieId {
		case 105: // id-ServedGUMMEIs -> ServedGUMMEIs (SEQUENCE OF ServedGUMMEIsItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 8)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedGUMMEIs length: %w", err)
			}
			result := make(ServedGUMMEIs, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedGUMMEIs item %d: %w", i, err)
				}
			}
			return &result, nil
		case 87: // id-RelativeMMECapacity -> RelativeMMECapacity (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RelativeMMECapacity (%d): %w", ieId, err)
			}
			result := RelativeMMECapacity(v)
			return &result, nil
		case 163: // id-MMERelaySupportIndicator -> MMERelaySupportIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMERelaySupportIndicator (%d): %w", ieId, err)
			}
			result := MMERelaySupportIndicator(v)
			return &result, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 228: // id-UE-RetentionInformation -> UE-RetentionInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-RetentionInformation (%d): %w", ieId, err)
			}
			result := UERetentionInformation(v)
			return &result, nil
		case 247: // id-ServedDCNs -> ServedDCNs (SEQUENCE OF ServedDCNsItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 32)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedDCNs length: %w", err)
			}
			result := make(ServedDCNs, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedDCNs item %d: %w", i, err)
				}
			}
			return &result, nil
		case 303: // id-IAB-Supported -> IAB-Supported (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IAB-Supported (%d): %w", ieId, err)
			}
			result := IABSupported(v)
			return &result, nil
		}
	case "S1SetupFailure", "S1SetupFailureIEs":
		switch ieId {
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 65: // id-TimeToWait -> TimeToWait (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 6, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeToWait (%d): %w", ieId, err)
			}
			result := TimeToWait(v)
			return &result, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENBConfigurationUpdate", "ENBConfigurationUpdateIEs":
		switch ieId {
		case 64: // id-SupportedTAs -> SupportedTAs (SEQUENCE OF SupportedTAsItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SupportedTAs length: %w", err)
			}
			result := make(SupportedTAs, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE SupportedTAs item %d: %w", i, err)
				}
			}
			return &result, nil
		case 128: // id-CSG-IdList -> CSG-IdList (SEQUENCE OF CSGIdListItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSG-IdList length: %w", err)
			}
			result := make(CSGIdList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE CSG-IdList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 137: // id-DefaultPagingDRX -> PagingDRX (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PagingDRX (%d): %w", ieId, err)
			}
			result := PagingDRX(v)
			return &result, nil
		case 234: // id-NB-IoT-DefaultPagingDRX -> NB-IoT-DefaultPagingDRX (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NB-IoT-DefaultPagingDRX (%d): %w", ieId, err)
			}
			result := NBIoTDefaultPagingDRX(v)
			return &result, nil
		case 292: // id-ConnectedengNBToAddList -> ConnectedengNBList (SEQUENCE OF ConnectedengNBItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ConnectedengNBList length: %w", err)
			}
			result := make(ConnectedengNBList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ConnectedengNBList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 293: // id-ConnectedengNBToRemoveList -> ConnectedengNBList (SEQUENCE OF ConnectedengNBItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ConnectedengNBList length: %w", err)
			}
			result := make(ConnectedengNBList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ConnectedengNBList item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "ENBConfigurationUpdateAcknowledge", "ENBConfigurationUpdateAcknowledgeIEs":
		switch ieId {
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENBConfigurationUpdateFailure", "ENBConfigurationUpdateFailureIEs":
		switch ieId {
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 65: // id-TimeToWait -> TimeToWait (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 6, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeToWait (%d): %w", ieId, err)
			}
			result := TimeToWait(v)
			return &result, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MMEConfigurationUpdate", "MMEConfigurationUpdateIEs":
		switch ieId {
		case 105: // id-ServedGUMMEIs -> ServedGUMMEIs (SEQUENCE OF ServedGUMMEIsItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 8)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedGUMMEIs length: %w", err)
			}
			result := make(ServedGUMMEIs, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedGUMMEIs item %d: %w", i, err)
				}
			}
			return &result, nil
		case 87: // id-RelativeMMECapacity -> RelativeMMECapacity (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RelativeMMECapacity (%d): %w", ieId, err)
			}
			result := RelativeMMECapacity(v)
			return &result, nil
		case 247: // id-ServedDCNs -> ServedDCNs (SEQUENCE OF ServedDCNsItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 32)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedDCNs length: %w", err)
			}
			result := make(ServedDCNs, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedDCNs item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "MMEConfigurationUpdateAcknowledge", "MMEConfigurationUpdateAcknowledgeIEs":
		switch ieId {
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MMEConfigurationUpdateFailure", "MMEConfigurationUpdateFailureIEs":
		switch ieId {
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 65: // id-TimeToWait -> TimeToWait (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 6, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeToWait (%d): %w", ieId, err)
			}
			result := TimeToWait(v)
			return &result, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "DownlinkS1cdma2000tunnelling", "DownlinkS1cdma2000tunnellingIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 12: // id-E-RABSubjecttoDataForwardingList -> ERABSubjecttoDataForwardingList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABSubjecttoDataForwardingList (%d): %w", ieId, err)
			}
			return &v, nil
		case 83: // id-cdma2000HOStatus -> Cdma2000HOStatus (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Cdma2000HOStatus (%d): %w", ieId, err)
			}
			result := Cdma2000HOStatus(v)
			return &result, nil
		case 71: // id-cdma2000RATType -> Cdma2000RATType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Cdma2000RATType (%d): %w", ieId, err)
			}
			result := Cdma2000RATType(v)
			return &result, nil
		case 70: // id-cdma2000PDU -> Cdma2000PDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Cdma2000PDU (%d): %w", ieId, err)
			}
			result := Cdma2000PDU(v)
			return &result, nil
		}
	case "UplinkS1cdma2000tunnelling", "UplinkS1cdma2000tunnellingIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 71: // id-cdma2000RATType -> Cdma2000RATType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Cdma2000RATType (%d): %w", ieId, err)
			}
			result := Cdma2000RATType(v)
			return &result, nil
		case 72: // id-cdma2000SectorID -> Cdma2000SectorID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Cdma2000SectorID (%d): %w", ieId, err)
			}
			result := Cdma2000SectorID(v)
			return &result, nil
		case 84: // id-cdma2000HORequiredIndication -> Cdma2000HORequiredIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Cdma2000HORequiredIndication (%d): %w", ieId, err)
			}
			result := Cdma2000HORequiredIndication(v)
			return &result, nil
		case 102: // id-cdma2000OneXSRVCCInfo -> Cdma2000OneXSRVCCInfo
			var v Cdma2000OneXSRVCCInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cdma2000OneXSRVCCInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 97: // id-cdma2000OneXRAND -> Cdma2000OneXRAND (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Cdma2000OneXRAND (%d): %w", ieId, err)
			}
			result := Cdma2000OneXRAND(v)
			return &result, nil
		case 70: // id-cdma2000PDU -> Cdma2000PDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Cdma2000PDU (%d): %w", ieId, err)
			}
			result := Cdma2000PDU(v)
			return &result, nil
		case 140: // id-EUTRANRoundTripDelayEstimationInfo -> EUTRANRoundTripDelayEstimationInfo (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(2047), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EUTRANRoundTripDelayEstimationInfo (%d): %w", ieId, err)
			}
			result := EUTRANRoundTripDelayEstimationInfo(v)
			return &result, nil
		}
	case "UECapabilityInfoIndication", "UECapabilityInfoIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 74: // id-UERadioCapability -> UERadioCapability (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapability (%d): %w", ieId, err)
			}
			result := UERadioCapability(v)
			return &result, nil
		case 198: // id-UERadioCapabilityForPaging -> UERadioCapabilityForPaging (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityForPaging (%d): %w", ieId, err)
			}
			result := UERadioCapabilityForPaging(v)
			return &result, nil
		case 263: // id-UE-Application-Layer-Measurement-Capability -> UE-Application-Layer-Measurement-Capability (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-Application-Layer-Measurement-Capability (%d): %w", ieId, err)
			}
			result := UEApplicationLayerMeasurementCapability{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 272: // id-LTE-M-Indication -> LTE-M-Indication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LTE-M-Indication (%d): %w", ieId, err)
			}
			result := LTEMIndication(v)
			return &result, nil
		case 315: // id-UERadioCapability-NR-Format -> UERadioCapability (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapability (%d): %w", ieId, err)
			}
			result := UERadioCapability(v)
			return &result, nil
		case 327: // id-UERadioCapabilityForPaging-NR-Format -> UERadioCapabilityForPaging (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityForPaging (%d): %w", ieId, err)
			}
			result := UERadioCapabilityForPaging(v)
			return &result, nil
		}
	case "ENBStatusTransfer", "ENBStatusTransferIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 90: // id-eNB-StatusTransfer-TransparentContainer -> ENB-StatusTransfer-TransparentContainer
			var v ENBStatusTransferTransparentContainer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ENB-StatusTransfer-TransparentContainer (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MMEStatusTransfer", "MMEStatusTransferIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 90: // id-eNB-StatusTransfer-TransparentContainer -> ENB-StatusTransfer-TransparentContainer
			var v ENBStatusTransferTransparentContainer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ENB-StatusTransfer-TransparentContainer (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "TraceStart", "TraceStartIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 25: // id-TraceActivation -> TraceActivation
			var v TraceActivation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TraceActivation (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "TraceFailureIndication", "TraceFailureIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 86: // id-E-UTRAN-Trace-ID -> E-UTRAN-Trace-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-UTRAN-Trace-ID (%d): %w", ieId, err)
			}
			result := EUTRANTraceID(v)
			return &result, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "DeactivateTrace", "DeactivateTraceIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 86: // id-E-UTRAN-Trace-ID -> E-UTRAN-Trace-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-UTRAN-Trace-ID (%d): %w", ieId, err)
			}
			result := EUTRANTraceID(v)
			return &result, nil
		}
	case "CellTrafficTrace", "CellTrafficTraceIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 86: // id-E-UTRAN-Trace-ID -> E-UTRAN-Trace-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-UTRAN-Trace-ID (%d): %w", ieId, err)
			}
			result := EUTRANTraceID(v)
			return &result, nil
		case 100: // id-EUTRAN-CGI -> EUTRAN-CGI
			var v EUTRANCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EUTRAN-CGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 131: // id-TraceCollectionEntityIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TransportLayerAddress (%d): %w", ieId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 166: // id-PrivacyIndicator -> PrivacyIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PrivacyIndicator (%d): %w", ieId, err)
			}
			result := PrivacyIndicator(v)
			return &result, nil
		}
	case "LocationReportingControl", "LocationReportingControlIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 98: // id-RequestType -> RequestType
			var v RequestType
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RequestType (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "LocationReportingFailureIndication", "LocationReportingFailureIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "LocationReport", "LocationReportIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 100: // id-EUTRAN-CGI -> EUTRAN-CGI
			var v EUTRANCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EUTRAN-CGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 67: // id-TAI -> TAI
			var v TAI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TAI (%d): %w", ieId, err)
			}
			return &v, nil
		case 98: // id-RequestType -> RequestType
			var v RequestType
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RequestType (%d): %w", ieId, err)
			}
			return &v, nil
		case 288: // id-PSCellInformation -> PSCellInformation
			var v PSCellInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE PSCellInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 339: // id-LTE-NTN-TAI-Information -> LTE-NTN-TAI-Information
			var v LTENTNTAIInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LTE-NTN-TAI-Information (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "OverloadStart", "OverloadStartIEs":
		switch ieId {
		case 101: // id-OverloadResponse -> OverloadResponse
			var v OverloadResponse
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE OverloadResponse (%d): %w", ieId, err)
			}
			return &v, nil
		case 154: // id-GUMMEIList -> GUMMEIList (SEQUENCE OF GUMMEI)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GUMMEIList length: %w", err)
			}
			result := make(GUMMEIList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE GUMMEIList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 161: // id-TrafficLoadReductionIndication -> TrafficLoadReductionIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(99), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TrafficLoadReductionIndication (%d): %w", ieId, err)
			}
			result := TrafficLoadReductionIndication(v)
			return &result, nil
		}
	case "OverloadStop", "OverloadStopIEs":
		switch ieId {
		case 154: // id-GUMMEIList -> GUMMEIList (SEQUENCE OF GUMMEI)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GUMMEIList length: %w", err)
			}
			result := make(GUMMEIList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE GUMMEIList item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "WriteReplaceWarningRequest", "WriteReplaceWarningRequestIEs":
		switch ieId {
		case 111: // id-MessageIdentifier -> MessageIdentifier (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MessageIdentifier (%d): %w", ieId, err)
			}
			result := MessageIdentifier{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 112: // id-SerialNumber -> SerialNumber (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SerialNumber (%d): %w", ieId, err)
			}
			result := SerialNumber{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 113: // id-WarningAreaList -> WarningAreaList
			var v WarningAreaList
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE WarningAreaList (%d): %w", ieId, err)
			}
			return &v, nil
		case 114: // id-RepetitionPeriod -> RepetitionPeriod (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RepetitionPeriod (%d): %w", ieId, err)
			}
			result := RepetitionPeriod(v)
			return &result, nil
		case 144: // id-ExtendedRepetitionPeriod -> ExtendedRepetitionPeriod (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(4096), int64Ptr(131071), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ExtendedRepetitionPeriod (%d): %w", ieId, err)
			}
			result := ExtendedRepetitionPeriod(v)
			return &result, nil
		case 115: // id-NumberofBroadcastRequest -> NumberofBroadcastRequest (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(65535), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NumberofBroadcastRequest (%d): %w", ieId, err)
			}
			result := NumberofBroadcastRequest(v)
			return &result, nil
		case 116: // id-WarningType -> WarningType (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 2, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE WarningType (%d): %w", ieId, err)
			}
			result := WarningType(v)
			return &result, nil
		case 117: // id-WarningSecurityInfo -> WarningSecurityInfo (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 50, 50, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE WarningSecurityInfo (%d): %w", ieId, err)
			}
			result := WarningSecurityInfo(v)
			return &result, nil
		case 118: // id-DataCodingScheme -> DataCodingScheme (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE DataCodingScheme (%d): %w", ieId, err)
			}
			result := DataCodingScheme{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 119: // id-WarningMessageContents -> WarningMessageContents (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 1, 9600, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE WarningMessageContents (%d): %w", ieId, err)
			}
			result := WarningMessageContents(v)
			return &result, nil
		case 142: // id-ConcurrentWarningMessageIndicator -> ConcurrentWarningMessageIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ConcurrentWarningMessageIndicator (%d): %w", ieId, err)
			}
			result := ConcurrentWarningMessageIndicator(v)
			return &result, nil
		case 286: // id-WarningAreaCoordinates -> WarningAreaCoordinates (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 1, 1024, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE WarningAreaCoordinates (%d): %w", ieId, err)
			}
			result := WarningAreaCoordinates(v)
			return &result, nil
		}
	case "WriteReplaceWarningResponse", "WriteReplaceWarningResponseIEs":
		switch ieId {
		case 111: // id-MessageIdentifier -> MessageIdentifier (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MessageIdentifier (%d): %w", ieId, err)
			}
			result := MessageIdentifier{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 112: // id-SerialNumber -> SerialNumber (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SerialNumber (%d): %w", ieId, err)
			}
			result := SerialNumber{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 120: // id-BroadcastCompletedAreaList -> BroadcastCompletedAreaList
			var v BroadcastCompletedAreaList
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE BroadcastCompletedAreaList (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENBDirectInformationTransfer", "ENBDirectInformationTransferIEs":
		switch ieId {
		case 121: // id-Inter-SystemInformationTransferTypeEDT -> InterSystemInformationTransferType
			var v InterSystemInformationTransferType
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE InterSystemInformationTransferType (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MMEDirectInformationTransfer", "MMEDirectInformationTransferIEs":
		switch ieId {
		case 122: // id-Inter-SystemInformationTransferTypeMDT -> InterSystemInformationTransferType
			var v InterSystemInformationTransferType
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE InterSystemInformationTransferType (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENBConfigurationTransfer", "ENBConfigurationTransferIEs":
		switch ieId {
		case 129: // id-SONConfigurationTransferECT -> SONConfigurationTransfer
			var v SONConfigurationTransfer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SONConfigurationTransfer (%d): %w", ieId, err)
			}
			return &v, nil
		case 294: // id-EN-DCSONConfigurationTransfer-ECT -> EN-DCSONConfigurationTransfer
			var v ENDCSONConfigurationTransfer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EN-DCSONConfigurationTransfer (%d): %w", ieId, err)
			}
			return &v, nil
		case 310: // id-IntersystemSONConfigurationTransferECT -> IntersystemSONConfigurationTransfer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IntersystemSONConfigurationTransfer (%d): %w", ieId, err)
			}
			result := IntersystemSONConfigurationTransfer(v)
			return &result, nil
		}
	case "MMEConfigurationTransfer", "MMEConfigurationTransferIEs":
		switch ieId {
		case 130: // id-SONConfigurationTransferMCT -> SONConfigurationTransfer
			var v SONConfigurationTransfer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SONConfigurationTransfer (%d): %w", ieId, err)
			}
			return &v, nil
		case 295: // id-EN-DCSONConfigurationTransfer-MCT -> EN-DCSONConfigurationTransfer
			var v ENDCSONConfigurationTransfer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EN-DCSONConfigurationTransfer (%d): %w", ieId, err)
			}
			return &v, nil
		case 309: // id-IntersystemSONConfigurationTransferMCT -> IntersystemSONConfigurationTransfer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IntersystemSONConfigurationTransfer (%d): %w", ieId, err)
			}
			result := IntersystemSONConfigurationTransfer(v)
			return &result, nil
		}
	case "KillRequest", "KillRequestIEs":
		switch ieId {
		case 111: // id-MessageIdentifier -> MessageIdentifier (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MessageIdentifier (%d): %w", ieId, err)
			}
			result := MessageIdentifier{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 112: // id-SerialNumber -> SerialNumber (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SerialNumber (%d): %w", ieId, err)
			}
			result := SerialNumber{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 113: // id-WarningAreaList -> WarningAreaList
			var v WarningAreaList
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE WarningAreaList (%d): %w", ieId, err)
			}
			return &v, nil
		case 191: // id-KillAllWarningMessages -> KillAllWarningMessages (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE KillAllWarningMessages (%d): %w", ieId, err)
			}
			result := KillAllWarningMessages(v)
			return &result, nil
		}
	case "KillResponse", "KillResponseIEs":
		switch ieId {
		case 111: // id-MessageIdentifier -> MessageIdentifier (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MessageIdentifier (%d): %w", ieId, err)
			}
			result := MessageIdentifier{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 112: // id-SerialNumber -> SerialNumber (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SerialNumber (%d): %w", ieId, err)
			}
			result := SerialNumber{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 141: // id-BroadcastCancelledAreaList -> BroadcastCancelledAreaList
			var v BroadcastCancelledAreaList
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE BroadcastCancelledAreaList (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "PWSRestartIndication", "PWSRestartIndicationIEs":
		switch ieId {
		case 182: // id-ECGIListForRestart -> ECGIListForRestart (SEQUENCE OF EUTRANCGI)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ECGIListForRestart length: %w", err)
			}
			result := make(ECGIListForRestart, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ECGIListForRestart item %d: %w", i, err)
				}
			}
			return &result, nil
		case 59: // id-Global-ENB-ID -> Global-ENB-ID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Global-ENB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		case 188: // id-TAIListForRestart -> TAIListForRestart (SEQUENCE OF TAI)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 2048)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TAIListForRestart length: %w", err)
			}
			result := make(TAIListForRestart, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE TAIListForRestart item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "PWSFailureIndication", "PWSFailureIndicationIEs":
		switch ieId {
		case 222: // id-PWSfailedECGIList -> PWSfailedECGIList (SEQUENCE OF EUTRANCGI)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PWSfailedECGIList length: %w", err)
			}
			result := make(PWSfailedECGIList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE PWSfailedECGIList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 59: // id-Global-ENB-ID -> Global-ENB-ID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Global-ENB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "DownlinkUEAssociatedLPPaTransport", "DownlinkUEAssociatedLPPaTransport-IEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 148: // id-Routing-ID -> Routing-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Routing-ID (%d): %w", ieId, err)
			}
			result := RoutingID(v)
			return &result, nil
		case 147: // id-LPPa-PDU -> LPPa-PDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LPPa-PDU (%d): %w", ieId, err)
			}
			result := LPPaPDU(v)
			return &result, nil
		}
	case "UplinkUEAssociatedLPPaTransport", "UplinkUEAssociatedLPPaTransport-IEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 148: // id-Routing-ID -> Routing-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Routing-ID (%d): %w", ieId, err)
			}
			result := RoutingID(v)
			return &result, nil
		case 147: // id-LPPa-PDU -> LPPa-PDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LPPa-PDU (%d): %w", ieId, err)
			}
			result := LPPaPDU(v)
			return &result, nil
		}
	case "DownlinkNonUEAssociatedLPPaTransport", "DownlinkNonUEAssociatedLPPaTransport-IEs":
		switch ieId {
		case 148: // id-Routing-ID -> Routing-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Routing-ID (%d): %w", ieId, err)
			}
			result := RoutingID(v)
			return &result, nil
		case 147: // id-LPPa-PDU -> LPPa-PDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LPPa-PDU (%d): %w", ieId, err)
			}
			result := LPPaPDU(v)
			return &result, nil
		}
	case "UplinkNonUEAssociatedLPPaTransport", "UplinkNonUEAssociatedLPPaTransport-IEs":
		switch ieId {
		case 148: // id-Routing-ID -> Routing-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Routing-ID (%d): %w", ieId, err)
			}
			result := RoutingID(v)
			return &result, nil
		case 147: // id-LPPa-PDU -> LPPa-PDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LPPa-PDU (%d): %w", ieId, err)
			}
			result := LPPaPDU(v)
			return &result, nil
		}
	case "ERABModificationIndication", "E-RABModificationIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 199: // id-E-RABToBeModifiedListBearerModInd -> ERABToBeModifiedListBearerModInd (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeModifiedListBearerModInd (%d): %w", ieId, err)
			}
			return &v, nil
		case 201: // id-E-RABNotToBeModifiedListBearerModInd -> ERABNotToBeModifiedListBearerModInd (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABNotToBeModifiedListBearerModInd (%d): %w", ieId, err)
			}
			return &v, nil
		case 226: // id-CSGMembershipInfo -> CSGMembershipInfo
			var v CSGMembershipInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CSGMembershipInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 176: // id-Tunnel-Information-for-BBF -> TunnelInformation
			var v TunnelInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TunnelInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 264: // id-SecondaryRATDataUsageReportList -> SecondaryRATDataUsageReportList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SecondaryRATDataUsageReportList (%d): %w", ieId, err)
			}
			return &v, nil
		case 189: // id-UserLocationInformation -> UserLocationInformation
			var v UserLocationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UserLocationInformation (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABToBeModifiedItemBearerModInd", "E-RABToBeModifiedItemBearerModIndIEs":
		switch ieId {
		case 200: // id-E-RABToBeModifiedItemBearerModInd -> ERABToBeModifiedItemBearerModInd
			var v ERABToBeModifiedItemBearerModInd
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeModifiedItemBearerModInd (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABNotToBeModifiedItemBearerModInd", "E-RABNotToBeModifiedItemBearerModIndIEs":
		switch ieId {
		case 202: // id-E-RABNotToBeModifiedItemBearerModInd -> ERABNotToBeModifiedItemBearerModInd
			var v ERABNotToBeModifiedItemBearerModInd
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABNotToBeModifiedItemBearerModInd (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABModificationConfirm", "E-RABModificationConfirmIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 203: // id-E-RABModifyListBearerModConf -> ERABModifyListBearerModConf (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABModifyListBearerModConf (%d): %w", ieId, err)
			}
			return &v, nil
		case 205: // id-E-RABFailedToModifyListBearerModConf -> E-RABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 210: // id-E-RABToBeReleasedListBearerModConf -> E-RABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 146: // id-CSGMembershipStatus -> CSGMembershipStatus (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGMembershipStatus (%d): %w", ieId, err)
			}
			result := CSGMembershipStatus(v)
			return &result, nil
		}
	case "ERABModifyItemBearerModConf", "E-RABModifyItemBearerModConfIEs":
		switch ieId {
		case 204: // id-E-RABModifyItemBearerModConf -> ERABModifyItemBearerModConf
			var v ERABModifyItemBearerModConf
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABModifyItemBearerModConf (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextModificationIndication", "UEContextModificationIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 226: // id-CSGMembershipInfo -> CSGMembershipInfo
			var v CSGMembershipInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CSGMembershipInfo (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextModificationConfirm", "UEContextModificationConfirmIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 146: // id-CSGMembershipStatus -> CSGMembershipStatus (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGMembershipStatus (%d): %w", ieId, err)
			}
			result := CSGMembershipStatus(v)
			return &result, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextSuspendRequest", "UEContextSuspendRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 213: // id-InformationOnRecommendedCellsAndENBsForPaging -> InformationOnRecommendedCellsAndENBsForPaging
			var v InformationOnRecommendedCellsAndENBsForPaging
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE InformationOnRecommendedCellsAndENBsForPaging (%d): %w", ieId, err)
			}
			return &v, nil
		case 212: // id-CellIdentifierAndCELevelForCECapableUEs -> CellIdentifierAndCELevelForCECapableUEs
			var v CellIdentifierAndCELevelForCECapableUEs
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellIdentifierAndCELevelForCECapableUEs (%d): %w", ieId, err)
			}
			return &v, nil
		case 264: // id-SecondaryRATDataUsageReportList -> SecondaryRATDataUsageReportList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SecondaryRATDataUsageReportList (%d): %w", ieId, err)
			}
			return &v, nil
		case 189: // id-UserLocationInformation -> UserLocationInformation
			var v UserLocationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UserLocationInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 297: // id-TimeSinceSecondaryNodeRelease -> TimeSinceSecondaryNodeRelease (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeSinceSecondaryNodeRelease (%d): %w", ieId, err)
			}
			result := TimeSinceSecondaryNodeRelease(v)
			return &result, nil
		}
	case "UEContextSuspendResponse", "UEContextSuspendResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 40: // id-SecurityContext -> SecurityContext
			var v SecurityContext
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SecurityContext (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextResumeRequest", "UEContextResumeRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 235: // id-E-RABFailedToResumeListResumeReq -> ERABFailedToResumeListResumeReq (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABFailedToResumeListResumeReq (%d): %w", ieId, err)
			}
			return &v, nil
		case 245: // id-RRC-Resume-Cause -> RRC-Establishment-Cause (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 5, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RRC-Establishment-Cause (%d): %w", ieId, err)
			}
			result := RRCEstablishmentCause(v)
			return &result, nil
		}
	case "ERABFailedToResumeItemResumeReq", "E-RABFailedToResumeItemResumeReqIEs":
		switch ieId {
		case 236: // id-E-RABFailedToResumeItemResumeReq -> ERABFailedToResumeItemResumeReq
			var v ERABFailedToResumeItemResumeReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABFailedToResumeItemResumeReq (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextResumeResponse", "UEContextResumeResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 237: // id-E-RABFailedToResumeListResumeRes -> ERABFailedToResumeListResumeRes (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABFailedToResumeListResumeRes (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 40: // id-SecurityContext -> SecurityContext
			var v SecurityContext
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SecurityContext (%d): %w", ieId, err)
			}
			return &v, nil
		case 283: // id-PendingDataIndication -> PendingDataIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PendingDataIndication (%d): %w", ieId, err)
			}
			result := PendingDataIndication(v)
			return &result, nil
		}
	case "ERABFailedToResumeItemResumeRes", "E-RABFailedToResumeItemResumeResIEs":
		switch ieId {
		case 238: // id-E-RABFailedToResumeItemResumeRes -> ERABFailedToResumeItemResumeRes
			var v ERABFailedToResumeItemResumeRes
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABFailedToResumeItemResumeRes (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextResumeFailure", "UEContextResumeFailureIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ConnectionEstablishmentIndication", "ConnectionEstablishmentIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 74: // id-UERadioCapability -> UERadioCapability (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapability (%d): %w", ieId, err)
			}
			result := UERadioCapability(v)
			return &result, nil
		case 251: // id-EnhancedCoverageRestricted -> EnhancedCoverageRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EnhancedCoverageRestricted (%d): %w", ieId, err)
			}
			result := EnhancedCoverageRestricted(v)
			return &result, nil
		case 253: // id-DL-CP-SecurityInformation -> DL-CP-SecurityInformation
			var v DLCPSecurityInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE DL-CP-SecurityInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 271: // id-CE-ModeBRestricted -> CE-ModeBRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CE-ModeBRestricted (%d): %w", ieId, err)
			}
			result := CEModeBRestricted(v)
			return &result, nil
		case 280: // id-EndIndication -> EndIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EndIndication (%d): %w", ieId, err)
			}
			result := EndIndication(v)
			return &result, nil
		case 278: // id-Subscription-Based-UE-DifferentiationInfo -> Subscription-Based-UE-DifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Subscription-Based-UE-DifferentiationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 252: // id-UE-Level-QoS-Parameters -> E-RABLevelQoSParameters
			var v ERABLevelQoSParameters
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE E-RABLevelQoSParameters (%d): %w", ieId, err)
			}
			return &v, nil
		case 314: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityID (%d): %w", ieId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		case 192: // id-Masked-IMEISV -> Masked-IMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Masked-IMEISV (%d): %w", ieId, err)
			}
			result := MaskedIMEISV{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "RetrieveUEInformation", "RetrieveUEInformationIEs":
		switch ieId {
		case 96: // id-S-TMSI -> S-TMSI
			var v STMSI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE S-TMSI (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEInformationTransfer", "UEInformationTransferIEs":
		switch ieId {
		case 96: // id-S-TMSI -> S-TMSI
			var v STMSI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE S-TMSI (%d): %w", ieId, err)
			}
			return &v, nil
		case 252: // id-UE-Level-QoS-Parameters -> E-RABLevelQoSParameters
			var v ERABLevelQoSParameters
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE E-RABLevelQoSParameters (%d): %w", ieId, err)
			}
			return &v, nil
		case 74: // id-UERadioCapability -> UERadioCapability (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapability (%d): %w", ieId, err)
			}
			result := UERadioCapability(v)
			return &result, nil
		case 278: // id-Subscription-Based-UE-DifferentiationInfo -> Subscription-Based-UE-DifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Subscription-Based-UE-DifferentiationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 283: // id-PendingDataIndication -> PendingDataIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PendingDataIndication (%d): %w", ieId, err)
			}
			result := PendingDataIndication(v)
			return &result, nil
		case 192: // id-Masked-IMEISV -> Masked-IMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Masked-IMEISV (%d): %w", ieId, err)
			}
			result := MaskedIMEISV{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ENBCPRelocationIndication", "ENBCPRelocationIndicationIEs":
		switch ieId {
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 96: // id-S-TMSI -> S-TMSI
			var v STMSI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE S-TMSI (%d): %w", ieId, err)
			}
			return &v, nil
		case 100: // id-EUTRAN-CGI -> EUTRAN-CGI
			var v EUTRANCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EUTRAN-CGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 67: // id-TAI -> TAI
			var v TAI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TAI (%d): %w", ieId, err)
			}
			return &v, nil
		case 254: // id-UL-CP-SecurityInformation -> UL-CP-SecurityInformation
			var v ULCPSecurityInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UL-CP-SecurityInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 339: // id-LTE-NTN-TAI-Information -> LTE-NTN-TAI-Information
			var v LTENTNTAIInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LTE-NTN-TAI-Information (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MMECPRelocationIndication", "MMECPRelocationIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		}
	case "SecondaryRATDataUsageReport", "SecondaryRATDataUsageReportIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MME-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MME-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENB-UE-S1AP-ID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 264: // id-SecondaryRATDataUsageReportList -> SecondaryRATDataUsageReportList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SecondaryRATDataUsageReportList (%d): %w", ieId, err)
			}
			return &v, nil
		case 266: // id-HandoverFlag -> HandoverFlag (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE HandoverFlag (%d): %w", ieId, err)
			}
			result := HandoverFlag(v)
			return &result, nil
		case 189: // id-UserLocationInformation -> UserLocationInformation
			var v UserLocationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UserLocationInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 297: // id-TimeSinceSecondaryNodeRelease -> TimeSinceSecondaryNodeRelease (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeSinceSecondaryNodeRelease (%d): %w", ieId, err)
			}
			result := TimeSinceSecondaryNodeRelease(v)
			return &result, nil
		}
	case "UERadioCapabilityIDMappingRequest", "UERadioCapabilityIDMappingRequestIEs":
		switch ieId {
		case 314: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityID (%d): %w", ieId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		}
	case "UERadioCapabilityIDMappingResponse", "UERadioCapabilityIDMappingResponseIEs":
		switch ieId {
		case 314: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityID (%d): %w", ieId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		case 74: // id-UERadioCapability -> UERadioCapability (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapability (%d): %w", ieId, err)
			}
			result := UERadioCapability(v)
			return &result, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "S1RemovalRequest", "S1RemovalRequestIEs":
		switch ieId {
		case 59: // id-Global-ENB-ID -> Global-ENB-ID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Global-ENB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "S1RemovalResponse", "S1RemovalResponseIEs":
		switch ieId {
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "S1RemovalFailure", "S1RemovalFailureIEs":
		switch ieId {
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	}
	return nil, nil
}

// decodeExtensionProtocolIEFieldListConstrained decodes a constrained SEQUENCE OF ProtocolIEField values from APER.
// with the given SIZE constraint bounds.
func decodeExtensionProtocolIEFieldListConstrained(bb *per.BitBuffer, lb, ub int64) ([]ProtocolIEField, error) {
	n, err := per.DecodeConstrainedWholeNumberAligned(bb, lb, ub)
	if err != nil {
		return nil, fmt.Errorf("decoding list length: %w", err)
	}
	result := make([]ProtocolIEField, n)
	for i := int64(0); i < n; i++ {
		if err := result[i].UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding item %d: %w", i, err)
		}
	}
	return result, nil
}

// DecodeExtensionFieldValue decodes a known extension open value using its object-set context and ID.
// Returns the decoded typed value, or nil if the combination is unknown.
func DecodeExtensionFieldValue(context string, extensionId int64, data []byte) (interface{}, error) {
	bb := per.NewBitBufferFromBytes(data)
	switch context {
	case "BearersSubjectToStatusTransferItemExtIEs", "Bearers-SubjectToStatusTransfer-ItemExtIEs":
		switch extensionId {
		case 179: // id-ULCOUNTValueExtended -> COUNTValueExtended
			var v COUNTValueExtended
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension COUNTValueExtended (%d): %w", extensionId, err)
			}
			return &v, nil
		case 180: // id-DLCOUNTValueExtended -> COUNTValueExtended
			var v COUNTValueExtended
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension COUNTValueExtended (%d): %w", extensionId, err)
			}
			return &v, nil
		case 181: // id-ReceiveStatusOfULPDCPSDUsExtended -> ReceiveStatusOfULPDCPSDUsExtended (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 1, 16384, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ReceiveStatusOfULPDCPSDUsExtended (%d): %w", extensionId, err)
			}
			result := ReceiveStatusOfULPDCPSDUsExtended{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 217: // id-ULCOUNTValuePDCP-SNlength18 -> COUNTvaluePDCP-SNlength18
			var v COUNTvaluePDCPSNlength18
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension COUNTvaluePDCP-SNlength18 (%d): %w", extensionId, err)
			}
			return &v, nil
		case 218: // id-DLCOUNTValuePDCP-SNlength18 -> COUNTvaluePDCP-SNlength18
			var v COUNTvaluePDCPSNlength18
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension COUNTvaluePDCP-SNlength18 (%d): %w", extensionId, err)
			}
			return &v, nil
		case 219: // id-ReceiveStatusOfULPDCPSDUsPDCP-SNlength18 -> ReceiveStatusOfULPDCPSDUsPDCP-SNlength18 (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 1, 131072, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ReceiveStatusOfULPDCPSDUsPDCP-SNlength18 (%d): %w", extensionId, err)
			}
			result := ReceiveStatusOfULPDCPSDUsPDCPSNlength18{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ERABInformationListItemExtIEs", "E-RABInformationListItem-ExtIEs":
		switch extensionId {
		case 317: // id-DAPSRequestInfo -> DAPSRequestInfo
			var v DAPSRequestInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension DAPSRequestInfo (%d): %w", extensionId, err)
			}
			return &v, nil
		case 328: // id-SourceTransportLayerAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 332: // id-SecurityIndication -> SecurityIndication
			var v SecurityIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SecurityIndication (%d): %w", extensionId, err)
			}
			return &v, nil
		case 340: // id-SourceNodeTransportLayerAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ERABQoSParametersExtIEs", "E-RABQoSParameters-ExtIEs":
		switch extensionId {
		case 273: // id-DownlinkPacketLossRate -> Packet-LossRate (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(1000), false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Packet-LossRate (%d): %w", extensionId, err)
			}
			result := PacketLossRate(v)
			return &result, nil
		case 274: // id-UplinkPacketLossRate -> Packet-LossRate (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(1000), false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Packet-LossRate (%d): %w", extensionId, err)
			}
			result := PacketLossRate(v)
			return &result, nil
		}
	case "GBRQosInformationExtIEs", "GBR-QosInformation-ExtIEs":
		switch extensionId {
		case 255: // id-extended-e-RAB-MaximumBitrateDL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(10000000001), int64Ptr(4000000000000), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			result := ExtendedBitRate(v)
			return &result, nil
		case 256: // id-extended-e-RAB-MaximumBitrateUL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(10000000001), int64Ptr(4000000000000), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			result := ExtendedBitRate(v)
			return &result, nil
		case 257: // id-extended-e-RAB-GuaranteedBitrateDL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(10000000001), int64Ptr(4000000000000), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			result := ExtendedBitRate(v)
			return &result, nil
		case 258: // id-extended-e-RAB-GuaranteedBitrateUL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(10000000001), int64Ptr(4000000000000), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			result := ExtendedBitRate(v)
			return &result, nil
		}
	case "HandoverRestrictionListExtIEs", "HandoverRestrictionList-ExtIEs":
		switch extensionId {
		case 261: // id-NRrestrictioninEPSasSecondaryRAT -> NRrestrictioninEPSasSecondaryRAT (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRrestrictioninEPSasSecondaryRAT (%d): %w", extensionId, err)
			}
			result := NRrestrictioninEPSasSecondaryRAT(v)
			return &result, nil
		case 270: // id-UnlicensedSpectrumRestriction -> UnlicensedSpectrumRestriction (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension UnlicensedSpectrumRestriction (%d): %w", extensionId, err)
			}
			result := UnlicensedSpectrumRestriction(v)
			return &result, nil
		case 282: // id-CNTypeRestrictions -> CNTypeRestrictions (SEQUENCE OF CNTypeRestrictionsItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CNTypeRestrictions length: %w", err)
			}
			result := make(CNTypeRestrictions, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension CNTypeRestrictions item %d: %w", i, err)
				}
			}
			return &result, nil
		case 287: // id-NRrestrictionin5GS -> NRrestrictionin5GS (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRrestrictionin5GS (%d): %w", extensionId, err)
			}
			result := NRrestrictionin5GS(v)
			return &result, nil
		case 290: // id-LastNG-RANPLMNIdentity -> PLMNidentity (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PLMNidentity (%d): %w", extensionId, err)
			}
			result := PLMNidentity(v)
			return &result, nil
		case 336: // id-RAT-Restrictions -> RAT-Restrictions (SEQUENCE OF RATRestrictionsItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16)
			if err != nil {
				return nil, fmt.Errorf("decoding extension RAT-Restrictions length: %w", err)
			}
			result := make(RATRestrictions, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension RAT-Restrictions item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "ImmediateMDTExtIEs", "ImmediateMDT-ExtIEs":
		switch extensionId {
		case 171: // id-M3Configuration -> M3Configuration
			var v M3Configuration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension M3Configuration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 172: // id-M4Configuration -> M4Configuration
			var v M4Configuration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension M4Configuration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 173: // id-M5Configuration -> M5Configuration
			var v M5Configuration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension M5Configuration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 174: // id-MDT-Location-Info -> MDT-Location-Info (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MDT-Location-Info (%d): %w", extensionId, err)
			}
			result := MDTLocationInfo{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 220: // id-M6Configuration -> M6Configuration
			var v M6Configuration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension M6Configuration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 221: // id-M7Configuration -> M7Configuration
			var v M7Configuration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension M7Configuration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 284: // id-BluetoothMeasurementConfiguration -> BluetoothMeasurementConfiguration
			var v BluetoothMeasurementConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension BluetoothMeasurementConfiguration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 285: // id-WLANMeasurementConfiguration -> WLANMeasurementConfiguration
			var v WLANMeasurementConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension WLANMeasurementConfiguration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 345: // id-SensorMeasurementConfiguration -> SensorMeasurementConfiguration
			var v SensorMeasurementConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SensorMeasurementConfiguration (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "LastVisitedEUTRANCellInformationExtIEs", "LastVisitedEUTRANCellInformation-ExtIEs":
		switch extensionId {
		case 167: // id-Time-UE-StayedInCell-EnhancedGranularity -> Time-UE-StayedInCell-EnhancedGranularity (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(40950), false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Time-UE-StayedInCell-EnhancedGranularity (%d): %w", extensionId, err)
			}
			result := TimeUEStayedInCellEnhancedGranularity(v)
			return &result, nil
		case 168: // id-HO-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension Cause (%d): %w", extensionId, err)
			}
			return &v, nil
		case 329: // id-lastVisitedPSCellList -> LastVisitedPSCellList (SEQUENCE OF LastVisitedPSCellInformation)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 8)
			if err != nil {
				return nil, fmt.Errorf("decoding extension LastVisitedPSCellList length: %w", err)
			}
			result := make(LastVisitedPSCellList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension LastVisitedPSCellList item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "LoggedMDTExtIEs", "LoggedMDT-ExtIEs":
		switch extensionId {
		case 284: // id-BluetoothMeasurementConfiguration -> BluetoothMeasurementConfiguration
			var v BluetoothMeasurementConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension BluetoothMeasurementConfiguration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 285: // id-WLANMeasurementConfiguration -> WLANMeasurementConfiguration
			var v WLANMeasurementConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension WLANMeasurementConfiguration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 344: // id-LoggedMDTTrigger -> LoggedMDTTrigger
			var v LoggedMDTTrigger
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension LoggedMDTTrigger (%d): %w", extensionId, err)
			}
			return &v, nil
		case 345: // id-SensorMeasurementConfiguration -> SensorMeasurementConfiguration
			var v SensorMeasurementConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SensorMeasurementConfiguration (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ProSeAuthorizedExtIEs", "ProSeAuthorized-ExtIEs":
		switch extensionId {
		case 216: // id-ProSeUEtoNetworkRelaying -> ProSeUEtoNetworkRelaying (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ProSeUEtoNetworkRelaying (%d): %w", extensionId, err)
			}
			result := ProSeUEtoNetworkRelaying(v)
			return &result, nil
		}
	case "RequestTypeExtIEs", "RequestType-ExtIEs":
		switch extensionId {
		case 298: // id-RequestTypeAdditionalInfo -> RequestTypeAdditionalInfo (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension RequestTypeAdditionalInfo (%d): %w", extensionId, err)
			}
			result := RequestTypeAdditionalInfo(v)
			return &result, nil
		}
	case "RLFReportInformationExtIEs", "RLFReportInformation-ExtIEs":
		switch extensionId {
		case 313: // id-NB-IoT-RLF-Report-Container -> NB-IoT-RLF-Report-Container (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NB-IoT-RLF-Report-Container (%d): %w", extensionId, err)
			}
			result := NBIoTRLFReportContainer(v)
			return &result, nil
		}
	case "SONInformationReplyExtIEs", "SONInformationReply-ExtIEs":
		switch extensionId {
		case 149: // id-Time-Synchronisation-Info -> TimeSynchronisationInfo
			var v TimeSynchronisationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension TimeSynchronisationInfo (%d): %w", extensionId, err)
			}
			return &v, nil
		case 208: // id-Muting-Pattern-Information -> MutingPatternInformation
			var v MutingPatternInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension MutingPatternInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "SONConfigurationTransferExtIEs", "SONConfigurationTransfer-ExtIEs":
		switch extensionId {
		case 152: // id-x2TNLConfigurationInfo -> X2TNLConfigurationInfo
			var v X2TNLConfigurationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension X2TNLConfigurationInfo (%d): %w", extensionId, err)
			}
			return &v, nil
		case 209: // id-Synchronisation-Information -> SynchronisationInformation
			var v SynchronisationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SynchronisationInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "SourceeNBToTargeteNBTransparentContainerExtIEs", "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs":
		switch extensionId {
		case 175: // id-MobilityInformation -> MobilityInformation (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MobilityInformation (%d): %w", extensionId, err)
			}
			result := MobilityInformation{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 194: // id-uE-HistoryInformationFromTheUE -> UE-HistoryInformationFromTheUE (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension UE-HistoryInformationFromTheUE (%d): %w", extensionId, err)
			}
			result := UEHistoryInformationFromTheUE(v)
			return &result, nil
		case 296: // id-IMSvoiceEPSfallbackfrom5G -> IMSvoiceEPSfallbackfrom5G (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension IMSvoiceEPSfallbackfrom5G (%d): %w", extensionId, err)
			}
			result := IMSvoiceEPSfallbackfrom5G(v)
			return &result, nil
		case 299: // id-AdditionalRRMPriorityIndex -> AdditionalRRMPriorityIndex (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension AdditionalRRMPriorityIndex (%d): %w", extensionId, err)
			}
			result := AdditionalRRMPriorityIndex{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 300: // id-ContextatSource -> ContextatSource
			var v ContextatSource
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension ContextatSource (%d): %w", extensionId, err)
			}
			return &v, nil
		case 311: // id-IntersystemMeasurementConfiguration -> IntersystemMeasurementConfiguration
			var v IntersystemMeasurementConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension IntersystemMeasurementConfiguration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 312: // id-SourceNodeID -> SourceNodeID
			var v SourceNodeID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SourceNodeID (%d): %w", extensionId, err)
			}
			return &v, nil
		case 326: // id-EmergencyIndicator -> EmergencyIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EmergencyIndicator (%d): %w", extensionId, err)
			}
			result := EmergencyIndicator(v)
			return &result, nil
		case 337: // id-UEContextReferenceatSourceeNB -> ENB-UE-S1AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ENB-UE-S1AP-ID (%d): %w", extensionId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 343: // id-SourceSNID -> Global-RAN-NODE-ID
			var v GlobalRANNODEID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension Global-RAN-NODE-ID (%d): %w", extensionId, err)
			}
			return &v, nil
		case 79: // id-Direct-Forwarding-Path-Availability -> Direct-Forwarding-Path-Availability (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Direct-Forwarding-Path-Availability (%d): %w", extensionId, err)
			}
			result := DirectForwardingPathAvailability(v)
			return &result, nil
		}
	case "ServedGUMMEIsItemExtIEs", "ServedGUMMEIsItem-ExtIEs":
		switch extensionId {
		case 170: // id-GUMMEIType -> GUMMEIType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension GUMMEIType (%d): %w", extensionId, err)
			}
			result := GUMMEIType(v)
			return &result, nil
		}
	case "SupportedTAsItemExtIEs", "SupportedTAs-Item-ExtIEs":
		switch extensionId {
		case 232: // id-RAT-Type -> RAT-Type (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension RAT-Type (%d): %w", extensionId, err)
			}
			result := RATType(v)
			return &result, nil
		}
	case "TimeSynchronisationInfoExtIEs", "TimeSynchronisationInfo-ExtIEs":
		switch extensionId {
		case 207: // id-Muting-Availability-Indication -> MutingAvailabilityIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MutingAvailabilityIndication (%d): %w", extensionId, err)
			}
			result := MutingAvailabilityIndication(v)
			return &result, nil
		}
	case "TargeteNBToSourceeNBTransparentContainerExtIEs", "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs":
		switch extensionId {
		case 318: // id-DAPSResponseInfoList -> DAPSResponseInfoList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeExtensionProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding extension DAPSResponseInfoList (%d): %w", extensionId, err)
			}
			return &v, nil
		case 330: // id-RACSIndication -> RACSIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension RACSIndication (%d): %w", extensionId, err)
			}
			result := RACSIndication(v)
			return &result, nil
		case 335: // id-E-RABSecurityResultList -> E-RABSecurityResultList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeExtensionProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding extension E-RABSecurityResultList (%d): %w", extensionId, err)
			}
			return &v, nil
		case 79: // id-Direct-Forwarding-Path-Availability -> Direct-Forwarding-Path-Availability (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Direct-Forwarding-Path-Availability (%d): %w", extensionId, err)
			}
			result := DirectForwardingPathAvailability(v)
			return &result, nil
		}
	case "TraceActivationExtIEs", "TraceActivation-ExtIEs":
		switch extensionId {
		case 162: // id-MDTConfiguration -> MDT-Configuration
			var v MDTConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension MDT-Configuration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 262: // id-UEAppLayerMeasConfig -> UEAppLayerMeasConfig
			var v UEAppLayerMeasConfig
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension UEAppLayerMeasConfig (%d): %w", extensionId, err)
			}
			return &v, nil
		case 316: // id-MDTConfigurationNR -> MDT-ConfigurationNR (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MDT-ConfigurationNR (%d): %w", extensionId, err)
			}
			result := MDTConfigurationNR(v)
			return &result, nil
		}
	case "UEAggregateMaximumBitratesExtIEs", "UEAggregate-MaximumBitrates-ExtIEs":
		switch extensionId {
		case 259: // id-extended-uEaggregateMaximumBitRateDL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(10000000001), int64Ptr(4000000000000), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			result := ExtendedBitRate(v)
			return &result, nil
		case 260: // id-extended-uEaggregateMaximumBitRateUL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(10000000001), int64Ptr(4000000000000), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			result := ExtendedBitRate(v)
			return &result, nil
		}
	case "UEAppLayerMeasConfigExtIEs", "UEAppLayerMeasConfig-ExtIEs":
		switch extensionId {
		case 276: // id-serviceType -> ServiceType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ServiceType (%d): %w", extensionId, err)
			}
			result := ServiceType(v)
			return &result, nil
		}
	case "UserLocationInformationExtIEs", "UserLocationInformation-ExtIEs":
		switch extensionId {
		case 288: // id-PSCellInformation -> PSCellInformation
			var v PSCellInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension PSCellInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		case 339: // id-LTE-NTN-TAI-Information -> LTE-NTN-TAI-Information
			var v LTENTNTAIInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension LTE-NTN-TAI-Information (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "X2TNLConfigurationInfoExtIEs", "X2TNLConfigurationInfo-ExtIEs":
		switch extensionId {
		case 153: // id-eNBX2ExtendedTransportLayerAddresses -> ENBX2ExtTLAs (SEQUENCE OF ENBX2ExtTLA)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ENBX2ExtTLAs length: %w", err)
			}
			result := make(ENBX2ExtTLAs, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension ENBX2ExtTLAs item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "ERABToBeSetupItemHOReqExtIEs", "E-RABToBeSetupItemHOReq-ExtIEs":
		switch extensionId {
		case 143: // id-Data-Forwarding-Not-Possible -> Data-Forwarding-Not-Possible (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Data-Forwarding-Not-Possible (%d): %w", extensionId, err)
			}
			result := DataForwardingNotPossible(v)
			return &result, nil
		case 233: // id-BearerType -> BearerType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension BearerType (%d): %w", extensionId, err)
			}
			result := BearerType(v)
			return &result, nil
		case 305: // id-Ethernet-Type -> Ethernet-Type (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Ethernet-Type (%d): %w", extensionId, err)
			}
			result := EthernetType(v)
			return &result, nil
		case 332: // id-SecurityIndication -> SecurityIndication
			var v SecurityIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SecurityIndication (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ERABToBeSwitchedDLItemExtIEs", "E-RABToBeSwitchedDLItem-ExtIEs":
		switch extensionId {
		case 332: // id-SecurityIndication -> SecurityIndication
			var v SecurityIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SecurityIndication (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ERABToBeSetupItemBearerSUReqExtIEs", "E-RABToBeSetupItemBearerSUReqExtIEs":
		switch extensionId {
		case 156: // id-Correlation-ID -> Correlation-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Correlation-ID (%d): %w", extensionId, err)
			}
			result := CorrelationID(v)
			return &result, nil
		case 183: // id-SIPTO-Correlation-ID -> Correlation-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Correlation-ID (%d): %w", extensionId, err)
			}
			result := CorrelationID(v)
			return &result, nil
		case 233: // id-BearerType -> BearerType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension BearerType (%d): %w", extensionId, err)
			}
			result := BearerType(v)
			return &result, nil
		case 305: // id-Ethernet-Type -> Ethernet-Type (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Ethernet-Type (%d): %w", extensionId, err)
			}
			result := EthernetType(v)
			return &result, nil
		case 332: // id-SecurityIndication -> SecurityIndication
			var v SecurityIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SecurityIndication (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ERABToBeModifyItemBearerModReqExtIEs", "E-RABToBeModifyItemBearerModReqExtIEs":
		switch extensionId {
		case 185: // id-TransportInformation -> TransportInformation
			var v TransportInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension TransportInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ERABToBeSetupItemCtxtSUReqExtIEs", "E-RABToBeSetupItemCtxtSUReqExtIEs":
		switch extensionId {
		case 156: // id-Correlation-ID -> Correlation-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Correlation-ID (%d): %w", extensionId, err)
			}
			result := CorrelationID(v)
			return &result, nil
		case 183: // id-SIPTO-Correlation-ID -> Correlation-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Correlation-ID (%d): %w", extensionId, err)
			}
			result := CorrelationID(v)
			return &result, nil
		case 233: // id-BearerType -> BearerType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension BearerType (%d): %w", extensionId, err)
			}
			result := BearerType(v)
			return &result, nil
		case 305: // id-Ethernet-Type -> Ethernet-Type (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Ethernet-Type (%d): %w", extensionId, err)
			}
			result := EthernetType(v)
			return &result, nil
		case 332: // id-SecurityIndication -> SecurityIndication
			var v SecurityIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SecurityIndication (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	}
	return nil, nil
}

// DecodedProtocolIEField contains one decoded protocol IE and its nested open-type fields.
// Field always retains the original open-type bytes, including for unknown/private IDs.
type DecodedProtocolIEField struct {
	Path       string
	ObjectSet  string
	Field      ProtocolIEField
	Value      interface{}
	Children   []DecodedProtocolIEField
	Extensions []DecodedProtocolExtensionField
}

// DecodedProtocolExtensionField contains one decoded protocol extension and its nested open-type fields.
// Field always retains the original open-type bytes, including for unknown/private IDs.
type DecodedProtocolExtensionField struct {
	Path        string
	ObjectSet   string
	Field       ProtocolExtensionField
	Value       interface{}
	ProtocolIEs []DecodedProtocolIEField
	Extensions  []DecodedProtocolExtensionField
}

// DecodedProtocolValue contains a decoded procedure value and all recursively decoded top-level open-type fields.
type DecodedProtocolValue struct {
	Value              interface{}
	ProtocolIEs        []DecodedProtocolIEField
	ProtocolExtensions []DecodedProtocolExtensionField
}

var protocolIEFieldObjectSets = map[string]string{
	"CellTrafficTrace.ProtocolIEs":                                                       "CellTrafficTraceIEs",
	"ConnectionEstablishmentIndication.ProtocolIEs":                                      "ConnectionEstablishmentIndicationIEs",
	"DeactivateTrace.ProtocolIEs":                                                        "DeactivateTraceIEs",
	"DownlinkNASTransport.ProtocolIEs":                                                   "DownlinkNASTransport-IEs",
	"DownlinkNonUEAssociatedLPPaTransport.ProtocolIEs":                                   "DownlinkNonUEAssociatedLPPaTransport-IEs",
	"DownlinkS1cdma2000tunnelling.ProtocolIEs":                                           "DownlinkS1cdma2000tunnellingIEs",
	"DownlinkUEAssociatedLPPaTransport.ProtocolIEs":                                      "DownlinkUEAssociatedLPPaTransport-IEs",
	"ENBCPRelocationIndication.ProtocolIEs":                                              "ENBCPRelocationIndicationIEs",
	"ENBConfigurationTransfer.ProtocolIEs":                                               "ENBConfigurationTransferIEs",
	"ENBConfigurationUpdate.ProtocolIEs":                                                 "ENBConfigurationUpdateIEs",
	"ENBConfigurationUpdateAcknowledge.ProtocolIEs":                                      "ENBConfigurationUpdateAcknowledgeIEs",
	"ENBConfigurationUpdateFailure.ProtocolIEs":                                          "ENBConfigurationUpdateFailureIEs",
	"ENBDirectInformationTransfer.ProtocolIEs":                                           "ENBDirectInformationTransferIEs",
	"ENBEarlyStatusTransfer.ProtocolIEs":                                                 "ENBEarlyStatusTransferIEs",
	"ENBEarlyStatusTransferTransparentContainer.BearersSubjectToEarlyStatusTransferList": "Bearers-SubjectToEarlyStatusTransfer-ItemIEs",
	"ENBStatusTransfer.ProtocolIEs":                                                      "ENBStatusTransferIEs",
	"ENBStatusTransferTransparentContainer.BearersSubjectToStatusTransferList":           "Bearers-SubjectToStatusTransfer-ItemIEs",
	"ERABModificationConfirm.ProtocolIEs":                                                "E-RABModificationConfirmIEs",
	"ERABModificationIndication.ProtocolIEs":                                             "E-RABModificationIndicationIEs",
	"ERABModifyRequest.ProtocolIEs":                                                      "E-RABModifyRequestIEs",
	"ERABModifyResponse.ProtocolIEs":                                                     "E-RABModifyResponseIEs",
	"ERABReleaseCommand.ProtocolIEs":                                                     "E-RABReleaseCommandIEs",
	"ERABReleaseIndication.ProtocolIEs":                                                  "E-RABReleaseIndicationIEs",
	"ERABReleaseResponse.ProtocolIEs":                                                    "E-RABReleaseResponseIEs",
	"ERABSetupRequest.ProtocolIEs":                                                       "E-RABSetupRequestIEs",
	"ERABSetupResponse.ProtocolIEs":                                                      "E-RABSetupResponseIEs",
	"ErrorIndication.ProtocolIEs":                                                        "ErrorIndicationIEs",
	"HandoverCancel.ProtocolIEs":                                                         "HandoverCancelIEs",
	"HandoverCancelAcknowledge.ProtocolIEs":                                              "HandoverCancelAcknowledgeIEs",
	"HandoverCommand.ProtocolIEs":                                                        "HandoverCommandIEs",
	"HandoverFailure.ProtocolIEs":                                                        "HandoverFailureIEs",
	"HandoverNotify.ProtocolIEs":                                                         "HandoverNotifyIEs",
	"HandoverPreparationFailure.ProtocolIEs":                                             "HandoverPreparationFailureIEs",
	"HandoverRequest.ProtocolIEs":                                                        "HandoverRequestIEs",
	"HandoverRequestAcknowledge.ProtocolIEs":                                             "HandoverRequestAcknowledgeIEs",
	"HandoverRequired.ProtocolIEs":                                                       "HandoverRequiredIEs",
	"HandoverSuccess.ProtocolIEs":                                                        "HandoverSuccessIEs",
	"InitialContextSetupFailure.ProtocolIEs":                                             "InitialContextSetupFailureIEs",
	"InitialContextSetupRequest.ProtocolIEs":                                             "InitialContextSetupRequestIEs",
	"InitialContextSetupResponse.ProtocolIEs":                                            "InitialContextSetupResponseIEs",
	"InitialUEMessage.ProtocolIEs":                                                       "InitialUEMessage-IEs",
	"KillRequest.ProtocolIEs":                                                            "KillRequestIEs",
	"KillResponse.ProtocolIEs":                                                           "KillResponseIEs",
	"LocationReport.ProtocolIEs":                                                         "LocationReportIEs",
	"LocationReportingControl.ProtocolIEs":                                               "LocationReportingControlIEs",
	"LocationReportingFailureIndication.ProtocolIEs":                                     "LocationReportingFailureIndicationIEs",
	"MMECPRelocationIndication.ProtocolIEs":                                              "MMECPRelocationIndicationIEs",
	"MMEConfigurationTransfer.ProtocolIEs":                                               "MMEConfigurationTransferIEs",
	"MMEConfigurationUpdate.ProtocolIEs":                                                 "MMEConfigurationUpdateIEs",
	"MMEConfigurationUpdateAcknowledge.ProtocolIEs":                                      "MMEConfigurationUpdateAcknowledgeIEs",
	"MMEConfigurationUpdateFailure.ProtocolIEs":                                          "MMEConfigurationUpdateFailureIEs",
	"MMEDirectInformationTransfer.ProtocolIEs":                                           "MMEDirectInformationTransferIEs",
	"MMEEarlyStatusTransfer.ProtocolIEs":                                                 "MMEEarlyStatusTransferIEs",
	"MMEStatusTransfer.ProtocolIEs":                                                      "MMEStatusTransferIEs",
	"NASDeliveryIndication.ProtocolIEs":                                                  "NASDeliveryIndicationIEs",
	"NASNonDeliveryIndication.ProtocolIEs":                                               "NASNonDeliveryIndication-IEs",
	"OverloadStart.ProtocolIEs":                                                          "OverloadStartIEs",
	"OverloadStop.ProtocolIEs":                                                           "OverloadStopIEs",
	"PWSFailureIndication.ProtocolIEs":                                                   "PWSFailureIndicationIEs",
	"PWSRestartIndication.ProtocolIEs":                                                   "PWSRestartIndicationIEs",
	"Paging.ProtocolIEs":                                                                 "PagingIEs",
	"PathSwitchRequest.ProtocolIEs":                                                      "PathSwitchRequestIEs",
	"PathSwitchRequestAcknowledge.ProtocolIEs":                                           "PathSwitchRequestAcknowledgeIEs",
	"PathSwitchRequestFailure.ProtocolIEs":                                               "PathSwitchRequestFailureIEs",
	"RecommendedCellsForPaging.RecommendedCellList":                                      "RecommendedCellItemIEs",
	"RecommendedENBsForPaging.RecommendedENBList":                                        "RecommendedENBItemIEs",
	"RerouteNASRequest.ProtocolIEs":                                                      "RerouteNASRequest-IEs",
	"Reset.ProtocolIEs":                                                                  "ResetIEs",
	"ResetAcknowledge.ProtocolIEs":                                                       "ResetAcknowledgeIEs",
	"RetrieveUEInformation.ProtocolIEs":                                                  "RetrieveUEInformationIEs",
	"S1SetupFailure.ProtocolIEs":                                                         "S1SetupFailureIEs",
	"S1SetupRequest.ProtocolIEs":                                                         "S1SetupRequestIEs",
	"S1SetupResponse.ProtocolIEs":                                                        "S1SetupResponseIEs",
	"SecondaryRATDataUsageReport.ProtocolIEs":                                            "SecondaryRATDataUsageReportIEs",
	"SecondaryRATDataUsageReportItem.ERABUsageReportList":                                "E-RABUsageReportItemIEs",
	"SourceeNBToTargeteNBTransparentContainer.ERABInformationList":                       "E-RABInformationListIEs",
	"TraceFailureIndication.ProtocolIEs":                                                 "TraceFailureIndicationIEs",
	"TraceStart.ProtocolIEs":                                                             "TraceStartIEs",
	"UECapabilityInfoIndication.ProtocolIEs":                                             "UECapabilityInfoIndicationIEs",
	"UEContextModificationConfirm.ProtocolIEs":                                           "UEContextModificationConfirmIEs",
	"UEContextModificationFailure.ProtocolIEs":                                           "UEContextModificationFailureIEs",
	"UEContextModificationIndication.ProtocolIEs":                                        "UEContextModificationIndicationIEs",
	"UEContextModificationRequest.ProtocolIEs":                                           "UEContextModificationRequestIEs",
	"UEContextModificationResponse.ProtocolIEs":                                          "UEContextModificationResponseIEs",
	"UEContextReleaseCommand.ProtocolIEs":                                                "UEContextReleaseCommand-IEs",
	"UEContextReleaseComplete.ProtocolIEs":                                               "UEContextReleaseComplete-IEs",
	"UEContextReleaseRequest.ProtocolIEs":                                                "UEContextReleaseRequest-IEs",
	"UEContextResumeFailure.ProtocolIEs":                                                 "UEContextResumeFailureIEs",
	"UEContextResumeRequest.ProtocolIEs":                                                 "UEContextResumeRequestIEs",
	"UEContextResumeResponse.ProtocolIEs":                                                "UEContextResumeResponseIEs",
	"UEContextSuspendRequest.ProtocolIEs":                                                "UEContextSuspendRequestIEs",
	"UEContextSuspendResponse.ProtocolIEs":                                               "UEContextSuspendResponseIEs",
	"UEInformationTransfer.ProtocolIEs":                                                  "UEInformationTransferIEs",
	"UERadioCapabilityIDMappingRequest.ProtocolIEs":                                      "UERadioCapabilityIDMappingRequestIEs",
	"UERadioCapabilityIDMappingResponse.ProtocolIEs":                                     "UERadioCapabilityIDMappingResponseIEs",
	"UERadioCapabilityMatchRequest.ProtocolIEs":                                          "UERadioCapabilityMatchRequestIEs",
	"UERadioCapabilityMatchResponse.ProtocolIEs":                                         "UERadioCapabilityMatchResponseIEs",
	"UplinkNASTransport.ProtocolIEs":                                                     "UplinkNASTransport-IEs",
	"UplinkNonUEAssociatedLPPaTransport.ProtocolIEs":                                     "UplinkNonUEAssociatedLPPaTransport-IEs",
	"UplinkS1cdma2000tunnelling.ProtocolIEs":                                             "UplinkS1cdma2000tunnellingIEs",
	"UplinkUEAssociatedLPPaTransport.ProtocolIEs":                                        "UplinkUEAssociatedLPPaTransport-IEs",
	"WriteReplaceWarningRequest.ProtocolIEs":                                             "WriteReplaceWarningRequestIEs",
	"WriteReplaceWarningResponse.ProtocolIEs":                                            "WriteReplaceWarningResponseIEs",
}

var protocolIETypeObjectSets = map[string]string{
	"BearersSubjectToEarlyStatusTransferList":   "Bearers-SubjectToEarlyStatusTransfer-ItemIEs",
	"BearersSubjectToStatusTransferList":        "Bearers-SubjectToStatusTransfer-ItemIEs",
	"DAPSResponseInfoList":                      "DAPSResponseInfoListIEs",
	"ERABAdmittedList":                          "E-RABAdmittedItemIEs",
	"ERABFailedToResumeListResumeReq":           "E-RABFailedToResumeItemResumeReqIEs",
	"ERABFailedToResumeListResumeRes":           "E-RABFailedToResumeItemResumeResIEs",
	"ERABFailedtoSetupListHOReqAck":             "E-RABFailedtoSetupItemHOReqAckIEs",
	"ERABInformationList":                       "E-RABInformationListIEs",
	"ERABList":                                  "E-RABItemIEs",
	"ERABModifyListBearerModConf":               "E-RABModifyItemBearerModConfIEs",
	"ERABModifyListBearerModRes":                "E-RABModifyItemBearerModResIEs",
	"ERABNotToBeModifiedListBearerModInd":       "E-RABNotToBeModifiedItemBearerModIndIEs",
	"ERABReleaseListBearerRelComp":              "E-RABReleaseItemBearerRelCompIEs",
	"ERABSecurityResultList":                    "E-RABSecurityResultListIEs",
	"ERABSetupListBearerSURes":                  "E-RABSetupItemBearerSUResIEs",
	"ERABSetupListCtxtSURes":                    "E-RABSetupItemCtxtSUResIEs",
	"ERABSubjecttoDataForwardingList":           "E-RABDataForwardingItemIEs",
	"ERABToBeModifiedListBearerModInd":          "E-RABToBeModifiedItemBearerModIndIEs",
	"ERABToBeModifiedListBearerModReq":          "E-RABToBeModifiedItemBearerModReqIEs",
	"ERABToBeSetupListBearerSUReq":              "E-RABToBeSetupItemBearerSUReqIEs",
	"ERABToBeSetupListCtxtSUReq":                "E-RABToBeSetupItemCtxtSUReqIEs",
	"ERABToBeSetupListHOReq":                    "E-RABToBeSetupItemHOReqIEs",
	"ERABToBeSwitchedDLList":                    "E-RABToBeSwitchedDLItemIEs",
	"ERABToBeSwitchedULList":                    "E-RABToBeSwitchedULItemIEs",
	"ERABToBeUpdatedList":                       "E-RABToBeUpdatedItemIEs",
	"ERABUsageReportList":                       "E-RABUsageReportItemIEs",
	"MDTModeExtension":                          "MDTMode-ExtensionIE",
	"RecommendedCellList":                       "RecommendedCellItemIEs",
	"RecommendedENBList":                        "RecommendedENBItemIEs",
	"SONInformationExtension":                   "SONInformation-ExtensionIE",
	"SecondaryRATDataUsageReportList":           "SecondaryRATDataUsageReportItemIEs",
	"TAIList":                                   "TAIItemIEs",
	"UEAssociatedLogicalS1ConnectionListRes":    "UE-associatedLogicalS1-ConnectionItemRes",
	"UEAssociatedLogicalS1ConnectionListResAck": "UE-associatedLogicalS1-ConnectionItemResAck",
}

var protocolExtensionFieldObjectSets = map[string]string{
	"BearersSubjectToStatusTransferItem.IEExtensions":         "Bearers-SubjectToStatusTransfer-ItemExtIEs",
	"ENBEarlyStatusTransferTransparentContainer.IEExtensions": "ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs",
	"ERABInformationListItem.IEExtensions":                    "E-RABInformationListItem-ExtIEs",
	"ERABLevelQoSParameters.IEExtensions":                     "E-RABQoSParameters-ExtIEs",
	"ERABToBeModifiedItemBearerModReq.IEExtensions":           "E-RABToBeModifyItemBearerModReqExtIEs",
	"ERABToBeSetupItemBearerSUReq.IEExtensions":               "E-RABToBeSetupItemBearerSUReqExtIEs",
	"ERABToBeSetupItemCtxtSUReq.IEExtensions":                 "E-RABToBeSetupItemCtxtSUReqExtIEs",
	"ERABToBeSetupItemHOReq.IEExtensions":                     "E-RABToBeSetupItemHOReq-ExtIEs",
	"ERABToBeSwitchedDLItem.IEExtensions":                     "E-RABToBeSwitchedDLItem-ExtIEs",
	"GBRQosInformation.IEExtensions":                          "GBR-QosInformation-ExtIEs",
	"HandoverRestrictionList.IEExtensions":                    "HandoverRestrictionList-ExtIEs",
	"ImmediateMDT.IEExtensions":                               "ImmediateMDT-ExtIEs",
	"LastVisitedEUTRANCellInformation.IEExtensions":           "LastVisitedEUTRANCellInformation-ExtIEs",
	"LoggedMDT.IEExtensions":                                  "LoggedMDT-ExtIEs",
	"M4Configuration.IEExtensions":                            "M4Configuration-ExtIEs",
	"M5Configuration.IEExtensions":                            "M5Configuration-ExtIEs",
	"M6Configuration.IEExtensions":                            "M6Configuration-ExtIEs",
	"M7Configuration.IEExtensions":                            "M7Configuration-ExtIEs",
	"MDTConfiguration.IEExtensions":                           "MDT-Configuration-ExtIEs",
	"ProSeAuthorized.IEExtensions":                            "ProSeAuthorized-ExtIEs",
	"RLFReportInformation.IEExtensions":                       "RLFReportInformation-ExtIEs",
	"RequestType.IEExtensions":                                "RequestType-ExtIEs",
	"SONConfigurationTransfer.IEExtensions":                   "SONConfigurationTransfer-ExtIEs",
	"SONInformationReply.IEExtensions":                        "SONInformationReply-ExtIEs",
	"ServedGUMMEIsItem.IEExtensions":                          "ServedGUMMEIsItem-ExtIEs",
	"SourceeNBToTargeteNBTransparentContainer.IEExtensions":   "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs",
	"SupportedTAsItem.IEExtensions":                           "SupportedTAs-Item-ExtIEs",
	"TargeteNBToSourceeNBTransparentContainer.IEExtensions":   "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs",
	"TimeSynchronisationInfo.IEExtensions":                    "TimeSynchronisationInfo-ExtIEs",
	"TraceActivation.IEExtensions":                            "TraceActivation-ExtIEs",
	"UEAggregateMaximumBitrate.IEExtensions":                  "UEAggregate-MaximumBitrates-ExtIEs",
	"UEAppLayerMeasConfig.IEExtensions":                       "UEAppLayerMeasConfig-ExtIEs",
	"UserLocationInformation.IEExtensions":                    "UserLocationInformation-ExtIEs",
	"X2TNLConfigurationInfo.IEExtensions":                     "X2TNLConfigurationInfo-ExtIEs",
}

var protocolExtensionTypeObjectSets = map[string]string{}

func protocolIEObjectSet(context string) string {
	switch context {
	case "Bearers-SubjectToDLDiscarding-ItemIEs":
		return "Bearers-SubjectToDLDiscarding-ItemIEs"
	case "Bearers-SubjectToEarlyStatusTransfer-ItemIEs":
		return "Bearers-SubjectToEarlyStatusTransfer-ItemIEs"
	case "Bearers-SubjectToStatusTransfer-ItemIEs":
		return "Bearers-SubjectToStatusTransfer-ItemIEs"
	case "BearersSubjectToDLDiscardingItem":
		return "Bearers-SubjectToDLDiscarding-ItemIEs"
	case "BearersSubjectToEarlyStatusTransferItem":
		return "Bearers-SubjectToEarlyStatusTransfer-ItemIEs"
	case "BearersSubjectToStatusTransferItem":
		return "Bearers-SubjectToStatusTransfer-ItemIEs"
	case "CellTrafficTrace":
		return "CellTrafficTraceIEs"
	case "CellTrafficTraceIEs":
		return "CellTrafficTraceIEs"
	case "ConnectionEstablishmentIndication":
		return "ConnectionEstablishmentIndicationIEs"
	case "ConnectionEstablishmentIndicationIEs":
		return "ConnectionEstablishmentIndicationIEs"
	case "DAPSResponseInfoList":
		return "DAPSResponseInfoListIEs"
	case "DAPSResponseInfoListIEs":
		return "DAPSResponseInfoListIEs"
	case "DeactivateTrace":
		return "DeactivateTraceIEs"
	case "DeactivateTraceIEs":
		return "DeactivateTraceIEs"
	case "DownlinkNASTransport":
		return "DownlinkNASTransport-IEs"
	case "DownlinkNASTransport-IEs":
		return "DownlinkNASTransport-IEs"
	case "DownlinkNonUEAssociatedLPPaTransport":
		return "DownlinkNonUEAssociatedLPPaTransport-IEs"
	case "DownlinkNonUEAssociatedLPPaTransport-IEs":
		return "DownlinkNonUEAssociatedLPPaTransport-IEs"
	case "DownlinkS1cdma2000tunnelling":
		return "DownlinkS1cdma2000tunnellingIEs"
	case "DownlinkS1cdma2000tunnellingIEs":
		return "DownlinkS1cdma2000tunnellingIEs"
	case "DownlinkUEAssociatedLPPaTransport":
		return "DownlinkUEAssociatedLPPaTransport-IEs"
	case "DownlinkUEAssociatedLPPaTransport-IEs":
		return "DownlinkUEAssociatedLPPaTransport-IEs"
	case "E-RABAdmittedItemIEs":
		return "E-RABAdmittedItemIEs"
	case "E-RABDataForwardingItemIEs":
		return "E-RABDataForwardingItemIEs"
	case "E-RABFailedToResumeItemResumeReqIEs":
		return "E-RABFailedToResumeItemResumeReqIEs"
	case "E-RABFailedToResumeItemResumeResIEs":
		return "E-RABFailedToResumeItemResumeResIEs"
	case "E-RABFailedtoSetupItemHOReqAckIEs":
		return "E-RABFailedtoSetupItemHOReqAckIEs"
	case "E-RABInformationListIEs":
		return "E-RABInformationListIEs"
	case "E-RABItemIEs":
		return "E-RABItemIEs"
	case "E-RABModificationConfirmIEs":
		return "E-RABModificationConfirmIEs"
	case "E-RABModificationIndicationIEs":
		return "E-RABModificationIndicationIEs"
	case "E-RABModifyItemBearerModConfIEs":
		return "E-RABModifyItemBearerModConfIEs"
	case "E-RABModifyItemBearerModResIEs":
		return "E-RABModifyItemBearerModResIEs"
	case "E-RABModifyRequestIEs":
		return "E-RABModifyRequestIEs"
	case "E-RABModifyResponseIEs":
		return "E-RABModifyResponseIEs"
	case "E-RABNotToBeModifiedItemBearerModIndIEs":
		return "E-RABNotToBeModifiedItemBearerModIndIEs"
	case "E-RABReleaseCommandIEs":
		return "E-RABReleaseCommandIEs"
	case "E-RABReleaseIndicationIEs":
		return "E-RABReleaseIndicationIEs"
	case "E-RABReleaseItemBearerRelCompIEs":
		return "E-RABReleaseItemBearerRelCompIEs"
	case "E-RABReleaseResponseIEs":
		return "E-RABReleaseResponseIEs"
	case "E-RABSecurityResultListIEs":
		return "E-RABSecurityResultListIEs"
	case "E-RABSetupItemBearerSUResIEs":
		return "E-RABSetupItemBearerSUResIEs"
	case "E-RABSetupItemCtxtSUResIEs":
		return "E-RABSetupItemCtxtSUResIEs"
	case "E-RABSetupRequestIEs":
		return "E-RABSetupRequestIEs"
	case "E-RABSetupResponseIEs":
		return "E-RABSetupResponseIEs"
	case "E-RABToBeModifiedItemBearerModIndIEs":
		return "E-RABToBeModifiedItemBearerModIndIEs"
	case "E-RABToBeModifiedItemBearerModReqIEs":
		return "E-RABToBeModifiedItemBearerModReqIEs"
	case "E-RABToBeSetupItemBearerSUReqIEs":
		return "E-RABToBeSetupItemBearerSUReqIEs"
	case "E-RABToBeSetupItemCtxtSUReqIEs":
		return "E-RABToBeSetupItemCtxtSUReqIEs"
	case "E-RABToBeSetupItemHOReqIEs":
		return "E-RABToBeSetupItemHOReqIEs"
	case "E-RABToBeSwitchedDLItemIEs":
		return "E-RABToBeSwitchedDLItemIEs"
	case "E-RABToBeSwitchedULItemIEs":
		return "E-RABToBeSwitchedULItemIEs"
	case "E-RABToBeUpdatedItemIEs":
		return "E-RABToBeUpdatedItemIEs"
	case "E-RABUsageReportItemIEs":
		return "E-RABUsageReportItemIEs"
	case "ENBCPRelocationIndication":
		return "ENBCPRelocationIndicationIEs"
	case "ENBCPRelocationIndicationIEs":
		return "ENBCPRelocationIndicationIEs"
	case "ENBConfigurationTransfer":
		return "ENBConfigurationTransferIEs"
	case "ENBConfigurationTransferIEs":
		return "ENBConfigurationTransferIEs"
	case "ENBConfigurationUpdate":
		return "ENBConfigurationUpdateIEs"
	case "ENBConfigurationUpdateAcknowledge":
		return "ENBConfigurationUpdateAcknowledgeIEs"
	case "ENBConfigurationUpdateAcknowledgeIEs":
		return "ENBConfigurationUpdateAcknowledgeIEs"
	case "ENBConfigurationUpdateFailure":
		return "ENBConfigurationUpdateFailureIEs"
	case "ENBConfigurationUpdateFailureIEs":
		return "ENBConfigurationUpdateFailureIEs"
	case "ENBConfigurationUpdateIEs":
		return "ENBConfigurationUpdateIEs"
	case "ENBDirectInformationTransfer":
		return "ENBDirectInformationTransferIEs"
	case "ENBDirectInformationTransferIEs":
		return "ENBDirectInformationTransferIEs"
	case "ENBEarlyStatusTransfer":
		return "ENBEarlyStatusTransferIEs"
	case "ENBEarlyStatusTransferIEs":
		return "ENBEarlyStatusTransferIEs"
	case "ENBStatusTransfer":
		return "ENBStatusTransferIEs"
	case "ENBStatusTransferIEs":
		return "ENBStatusTransferIEs"
	case "ERABAdmittedItem":
		return "E-RABAdmittedItemIEs"
	case "ERABDataForwardingItem":
		return "E-RABDataForwardingItemIEs"
	case "ERABFailedToResumeItemResumeReq":
		return "E-RABFailedToResumeItemResumeReqIEs"
	case "ERABFailedToResumeItemResumeRes":
		return "E-RABFailedToResumeItemResumeResIEs"
	case "ERABFailedtoSetupItemHOReqAck":
		return "E-RABFailedtoSetupItemHOReqAckIEs"
	case "ERABInformationList":
		return "E-RABInformationListIEs"
	case "ERABItem":
		return "E-RABItemIEs"
	case "ERABModificationConfirm":
		return "E-RABModificationConfirmIEs"
	case "ERABModificationIndication":
		return "E-RABModificationIndicationIEs"
	case "ERABModifyItemBearerModConf":
		return "E-RABModifyItemBearerModConfIEs"
	case "ERABModifyItemBearerModRes":
		return "E-RABModifyItemBearerModResIEs"
	case "ERABModifyRequest":
		return "E-RABModifyRequestIEs"
	case "ERABModifyResponse":
		return "E-RABModifyResponseIEs"
	case "ERABNotToBeModifiedItemBearerModInd":
		return "E-RABNotToBeModifiedItemBearerModIndIEs"
	case "ERABReleaseCommand":
		return "E-RABReleaseCommandIEs"
	case "ERABReleaseIndication":
		return "E-RABReleaseIndicationIEs"
	case "ERABReleaseItemBearerRelComp":
		return "E-RABReleaseItemBearerRelCompIEs"
	case "ERABReleaseResponse":
		return "E-RABReleaseResponseIEs"
	case "ERABSecurityResultList":
		return "E-RABSecurityResultListIEs"
	case "ERABSetupItemBearerSURes":
		return "E-RABSetupItemBearerSUResIEs"
	case "ERABSetupItemCtxtSURes":
		return "E-RABSetupItemCtxtSUResIEs"
	case "ERABSetupRequest":
		return "E-RABSetupRequestIEs"
	case "ERABSetupResponse":
		return "E-RABSetupResponseIEs"
	case "ERABToBeModifiedItemBearerModInd":
		return "E-RABToBeModifiedItemBearerModIndIEs"
	case "ERABToBeModifiedItemBearerModReq":
		return "E-RABToBeModifiedItemBearerModReqIEs"
	case "ERABToBeSetupItemBearerSUReq":
		return "E-RABToBeSetupItemBearerSUReqIEs"
	case "ERABToBeSetupItemCtxtSUReq":
		return "E-RABToBeSetupItemCtxtSUReqIEs"
	case "ERABToBeSetupItemHOReq":
		return "E-RABToBeSetupItemHOReqIEs"
	case "ERABToBeSwitchedDLItem":
		return "E-RABToBeSwitchedDLItemIEs"
	case "ERABToBeSwitchedULItem":
		return "E-RABToBeSwitchedULItemIEs"
	case "ERABToBeUpdatedItem":
		return "E-RABToBeUpdatedItemIEs"
	case "ERABUsageReportItem":
		return "E-RABUsageReportItemIEs"
	case "ErrorIndication":
		return "ErrorIndicationIEs"
	case "ErrorIndicationIEs":
		return "ErrorIndicationIEs"
	case "HandoverCancel":
		return "HandoverCancelIEs"
	case "HandoverCancelAcknowledge":
		return "HandoverCancelAcknowledgeIEs"
	case "HandoverCancelAcknowledgeIEs":
		return "HandoverCancelAcknowledgeIEs"
	case "HandoverCancelIEs":
		return "HandoverCancelIEs"
	case "HandoverCommand":
		return "HandoverCommandIEs"
	case "HandoverCommandIEs":
		return "HandoverCommandIEs"
	case "HandoverFailure":
		return "HandoverFailureIEs"
	case "HandoverFailureIEs":
		return "HandoverFailureIEs"
	case "HandoverNotify":
		return "HandoverNotifyIEs"
	case "HandoverNotifyIEs":
		return "HandoverNotifyIEs"
	case "HandoverPreparationFailure":
		return "HandoverPreparationFailureIEs"
	case "HandoverPreparationFailureIEs":
		return "HandoverPreparationFailureIEs"
	case "HandoverRequest":
		return "HandoverRequestIEs"
	case "HandoverRequestAcknowledge":
		return "HandoverRequestAcknowledgeIEs"
	case "HandoverRequestAcknowledgeIEs":
		return "HandoverRequestAcknowledgeIEs"
	case "HandoverRequestIEs":
		return "HandoverRequestIEs"
	case "HandoverRequired":
		return "HandoverRequiredIEs"
	case "HandoverRequiredIEs":
		return "HandoverRequiredIEs"
	case "HandoverSuccess":
		return "HandoverSuccessIEs"
	case "HandoverSuccessIEs":
		return "HandoverSuccessIEs"
	case "InitialContextSetupFailure":
		return "InitialContextSetupFailureIEs"
	case "InitialContextSetupFailureIEs":
		return "InitialContextSetupFailureIEs"
	case "InitialContextSetupRequest":
		return "InitialContextSetupRequestIEs"
	case "InitialContextSetupRequestIEs":
		return "InitialContextSetupRequestIEs"
	case "InitialContextSetupResponse":
		return "InitialContextSetupResponseIEs"
	case "InitialContextSetupResponseIEs":
		return "InitialContextSetupResponseIEs"
	case "InitialUEMessage":
		return "InitialUEMessage-IEs"
	case "InitialUEMessage-IEs":
		return "InitialUEMessage-IEs"
	case "KillRequest":
		return "KillRequestIEs"
	case "KillRequestIEs":
		return "KillRequestIEs"
	case "KillResponse":
		return "KillResponseIEs"
	case "KillResponseIEs":
		return "KillResponseIEs"
	case "LocationReport":
		return "LocationReportIEs"
	case "LocationReportIEs":
		return "LocationReportIEs"
	case "LocationReportingControl":
		return "LocationReportingControlIEs"
	case "LocationReportingControlIEs":
		return "LocationReportingControlIEs"
	case "LocationReportingFailureIndication":
		return "LocationReportingFailureIndicationIEs"
	case "LocationReportingFailureIndicationIEs":
		return "LocationReportingFailureIndicationIEs"
	case "MDTMode-ExtensionIE":
		return "MDTMode-ExtensionIE"
	case "MDTModeExtensionIE":
		return "MDTMode-ExtensionIE"
	case "MMECPRelocationIndication":
		return "MMECPRelocationIndicationIEs"
	case "MMECPRelocationIndicationIEs":
		return "MMECPRelocationIndicationIEs"
	case "MMEConfigurationTransfer":
		return "MMEConfigurationTransferIEs"
	case "MMEConfigurationTransferIEs":
		return "MMEConfigurationTransferIEs"
	case "MMEConfigurationUpdate":
		return "MMEConfigurationUpdateIEs"
	case "MMEConfigurationUpdateAcknowledge":
		return "MMEConfigurationUpdateAcknowledgeIEs"
	case "MMEConfigurationUpdateAcknowledgeIEs":
		return "MMEConfigurationUpdateAcknowledgeIEs"
	case "MMEConfigurationUpdateFailure":
		return "MMEConfigurationUpdateFailureIEs"
	case "MMEConfigurationUpdateFailureIEs":
		return "MMEConfigurationUpdateFailureIEs"
	case "MMEConfigurationUpdateIEs":
		return "MMEConfigurationUpdateIEs"
	case "MMEDirectInformationTransfer":
		return "MMEDirectInformationTransferIEs"
	case "MMEDirectInformationTransferIEs":
		return "MMEDirectInformationTransferIEs"
	case "MMEEarlyStatusTransfer":
		return "MMEEarlyStatusTransferIEs"
	case "MMEEarlyStatusTransferIEs":
		return "MMEEarlyStatusTransferIEs"
	case "MMEStatusTransfer":
		return "MMEStatusTransferIEs"
	case "MMEStatusTransferIEs":
		return "MMEStatusTransferIEs"
	case "NASDeliveryIndication":
		return "NASDeliveryIndicationIEs"
	case "NASDeliveryIndicationIEs":
		return "NASDeliveryIndicationIEs"
	case "NASNonDeliveryIndication":
		return "NASNonDeliveryIndication-IEs"
	case "NASNonDeliveryIndication-IEs":
		return "NASNonDeliveryIndication-IEs"
	case "OverloadStart":
		return "OverloadStartIEs"
	case "OverloadStartIEs":
		return "OverloadStartIEs"
	case "OverloadStop":
		return "OverloadStopIEs"
	case "OverloadStopIEs":
		return "OverloadStopIEs"
	case "PWSFailureIndication":
		return "PWSFailureIndicationIEs"
	case "PWSFailureIndicationIEs":
		return "PWSFailureIndicationIEs"
	case "PWSRestartIndication":
		return "PWSRestartIndicationIEs"
	case "PWSRestartIndicationIEs":
		return "PWSRestartIndicationIEs"
	case "Paging":
		return "PagingIEs"
	case "PagingIEs":
		return "PagingIEs"
	case "PathSwitchRequest":
		return "PathSwitchRequestIEs"
	case "PathSwitchRequestAcknowledge":
		return "PathSwitchRequestAcknowledgeIEs"
	case "PathSwitchRequestAcknowledgeIEs":
		return "PathSwitchRequestAcknowledgeIEs"
	case "PathSwitchRequestFailure":
		return "PathSwitchRequestFailureIEs"
	case "PathSwitchRequestFailureIEs":
		return "PathSwitchRequestFailureIEs"
	case "PathSwitchRequestIEs":
		return "PathSwitchRequestIEs"
	case "RecommendedCellItem":
		return "RecommendedCellItemIEs"
	case "RecommendedCellItemIEs":
		return "RecommendedCellItemIEs"
	case "RecommendedENBItem":
		return "RecommendedENBItemIEs"
	case "RecommendedENBItemIEs":
		return "RecommendedENBItemIEs"
	case "RerouteNASRequest":
		return "RerouteNASRequest-IEs"
	case "RerouteNASRequest-IEs":
		return "RerouteNASRequest-IEs"
	case "Reset":
		return "ResetIEs"
	case "ResetAcknowledge":
		return "ResetAcknowledgeIEs"
	case "ResetAcknowledgeIEs":
		return "ResetAcknowledgeIEs"
	case "ResetIEs":
		return "ResetIEs"
	case "RetrieveUEInformation":
		return "RetrieveUEInformationIEs"
	case "RetrieveUEInformationIEs":
		return "RetrieveUEInformationIEs"
	case "S1RemovalFailure":
		return "S1RemovalFailureIEs"
	case "S1RemovalFailureIEs":
		return "S1RemovalFailureIEs"
	case "S1RemovalRequest":
		return "S1RemovalRequestIEs"
	case "S1RemovalRequestIEs":
		return "S1RemovalRequestIEs"
	case "S1RemovalResponse":
		return "S1RemovalResponseIEs"
	case "S1RemovalResponseIEs":
		return "S1RemovalResponseIEs"
	case "S1SetupFailure":
		return "S1SetupFailureIEs"
	case "S1SetupFailureIEs":
		return "S1SetupFailureIEs"
	case "S1SetupRequest":
		return "S1SetupRequestIEs"
	case "S1SetupRequestIEs":
		return "S1SetupRequestIEs"
	case "S1SetupResponse":
		return "S1SetupResponseIEs"
	case "S1SetupResponseIEs":
		return "S1SetupResponseIEs"
	case "SONInformation-ExtensionIE":
		return "SONInformation-ExtensionIE"
	case "SONInformationExtensionIE":
		return "SONInformation-ExtensionIE"
	case "SecondaryRATDataUsageReport":
		return "SecondaryRATDataUsageReportIEs"
	case "SecondaryRATDataUsageReportIEs":
		return "SecondaryRATDataUsageReportIEs"
	case "SecondaryRATDataUsageReportItem":
		return "SecondaryRATDataUsageReportItemIEs"
	case "SecondaryRATDataUsageReportItemIEs":
		return "SecondaryRATDataUsageReportItemIEs"
	case "TAIItem":
		return "TAIItemIEs"
	case "TAIItemIEs":
		return "TAIItemIEs"
	case "TraceFailureIndication":
		return "TraceFailureIndicationIEs"
	case "TraceFailureIndicationIEs":
		return "TraceFailureIndicationIEs"
	case "TraceStart":
		return "TraceStartIEs"
	case "TraceStartIEs":
		return "TraceStartIEs"
	case "UE-associatedLogicalS1-ConnectionItemRes":
		return "UE-associatedLogicalS1-ConnectionItemRes"
	case "UE-associatedLogicalS1-ConnectionItemResAck":
		return "UE-associatedLogicalS1-ConnectionItemResAck"
	case "UEAssociatedLogicalS1ConnectionItemRes":
		return "UE-associatedLogicalS1-ConnectionItemRes"
	case "UEAssociatedLogicalS1ConnectionItemResAck":
		return "UE-associatedLogicalS1-ConnectionItemResAck"
	case "UECapabilityInfoIndication":
		return "UECapabilityInfoIndicationIEs"
	case "UECapabilityInfoIndicationIEs":
		return "UECapabilityInfoIndicationIEs"
	case "UEContextModificationConfirm":
		return "UEContextModificationConfirmIEs"
	case "UEContextModificationConfirmIEs":
		return "UEContextModificationConfirmIEs"
	case "UEContextModificationFailure":
		return "UEContextModificationFailureIEs"
	case "UEContextModificationFailureIEs":
		return "UEContextModificationFailureIEs"
	case "UEContextModificationIndication":
		return "UEContextModificationIndicationIEs"
	case "UEContextModificationIndicationIEs":
		return "UEContextModificationIndicationIEs"
	case "UEContextModificationRequest":
		return "UEContextModificationRequestIEs"
	case "UEContextModificationRequestIEs":
		return "UEContextModificationRequestIEs"
	case "UEContextModificationResponse":
		return "UEContextModificationResponseIEs"
	case "UEContextModificationResponseIEs":
		return "UEContextModificationResponseIEs"
	case "UEContextReleaseCommand":
		return "UEContextReleaseCommand-IEs"
	case "UEContextReleaseCommand-IEs":
		return "UEContextReleaseCommand-IEs"
	case "UEContextReleaseComplete":
		return "UEContextReleaseComplete-IEs"
	case "UEContextReleaseComplete-IEs":
		return "UEContextReleaseComplete-IEs"
	case "UEContextReleaseRequest":
		return "UEContextReleaseRequest-IEs"
	case "UEContextReleaseRequest-IEs":
		return "UEContextReleaseRequest-IEs"
	case "UEContextResumeFailure":
		return "UEContextResumeFailureIEs"
	case "UEContextResumeFailureIEs":
		return "UEContextResumeFailureIEs"
	case "UEContextResumeRequest":
		return "UEContextResumeRequestIEs"
	case "UEContextResumeRequestIEs":
		return "UEContextResumeRequestIEs"
	case "UEContextResumeResponse":
		return "UEContextResumeResponseIEs"
	case "UEContextResumeResponseIEs":
		return "UEContextResumeResponseIEs"
	case "UEContextSuspendRequest":
		return "UEContextSuspendRequestIEs"
	case "UEContextSuspendRequestIEs":
		return "UEContextSuspendRequestIEs"
	case "UEContextSuspendResponse":
		return "UEContextSuspendResponseIEs"
	case "UEContextSuspendResponseIEs":
		return "UEContextSuspendResponseIEs"
	case "UEInformationTransfer":
		return "UEInformationTransferIEs"
	case "UEInformationTransferIEs":
		return "UEInformationTransferIEs"
	case "UERadioCapabilityIDMappingRequest":
		return "UERadioCapabilityIDMappingRequestIEs"
	case "UERadioCapabilityIDMappingRequestIEs":
		return "UERadioCapabilityIDMappingRequestIEs"
	case "UERadioCapabilityIDMappingResponse":
		return "UERadioCapabilityIDMappingResponseIEs"
	case "UERadioCapabilityIDMappingResponseIEs":
		return "UERadioCapabilityIDMappingResponseIEs"
	case "UERadioCapabilityMatchRequest":
		return "UERadioCapabilityMatchRequestIEs"
	case "UERadioCapabilityMatchRequestIEs":
		return "UERadioCapabilityMatchRequestIEs"
	case "UERadioCapabilityMatchResponse":
		return "UERadioCapabilityMatchResponseIEs"
	case "UERadioCapabilityMatchResponseIEs":
		return "UERadioCapabilityMatchResponseIEs"
	case "UplinkNASTransport":
		return "UplinkNASTransport-IEs"
	case "UplinkNASTransport-IEs":
		return "UplinkNASTransport-IEs"
	case "UplinkNonUEAssociatedLPPaTransport":
		return "UplinkNonUEAssociatedLPPaTransport-IEs"
	case "UplinkNonUEAssociatedLPPaTransport-IEs":
		return "UplinkNonUEAssociatedLPPaTransport-IEs"
	case "UplinkS1cdma2000tunnelling":
		return "UplinkS1cdma2000tunnellingIEs"
	case "UplinkS1cdma2000tunnellingIEs":
		return "UplinkS1cdma2000tunnellingIEs"
	case "UplinkUEAssociatedLPPaTransport":
		return "UplinkUEAssociatedLPPaTransport-IEs"
	case "UplinkUEAssociatedLPPaTransport-IEs":
		return "UplinkUEAssociatedLPPaTransport-IEs"
	case "WriteReplaceWarningRequest":
		return "WriteReplaceWarningRequestIEs"
	case "WriteReplaceWarningRequestIEs":
		return "WriteReplaceWarningRequestIEs"
	case "WriteReplaceWarningResponse":
		return "WriteReplaceWarningResponseIEs"
	case "WriteReplaceWarningResponseIEs":
		return "WriteReplaceWarningResponseIEs"
	default:
		return context
	}
}

func protocolExtensionObjectSet(context string) string {
	switch context {
	case "Bearers-SubjectToStatusTransfer-ItemExtIEs":
		return "Bearers-SubjectToStatusTransfer-ItemExtIEs"
	case "BearersSubjectToStatusTransferItemExtIEs":
		return "Bearers-SubjectToStatusTransfer-ItemExtIEs"
	case "E-RABInformationListItem-ExtIEs":
		return "E-RABInformationListItem-ExtIEs"
	case "E-RABQoSParameters-ExtIEs":
		return "E-RABQoSParameters-ExtIEs"
	case "E-RABToBeModifyItemBearerModReqExtIEs":
		return "E-RABToBeModifyItemBearerModReqExtIEs"
	case "E-RABToBeSetupItemBearerSUReqExtIEs":
		return "E-RABToBeSetupItemBearerSUReqExtIEs"
	case "E-RABToBeSetupItemCtxtSUReqExtIEs":
		return "E-RABToBeSetupItemCtxtSUReqExtIEs"
	case "E-RABToBeSetupItemHOReq-ExtIEs":
		return "E-RABToBeSetupItemHOReq-ExtIEs"
	case "E-RABToBeSwitchedDLItem-ExtIEs":
		return "E-RABToBeSwitchedDLItem-ExtIEs"
	case "ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs":
		return "ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs"
	case "ENBEarlyStatusTransferTransparentContainerExtIEs":
		return "ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs"
	case "ERABInformationListItemExtIEs":
		return "E-RABInformationListItem-ExtIEs"
	case "ERABQoSParametersExtIEs":
		return "E-RABQoSParameters-ExtIEs"
	case "ERABToBeModifyItemBearerModReqExtIEs":
		return "E-RABToBeModifyItemBearerModReqExtIEs"
	case "ERABToBeSetupItemBearerSUReqExtIEs":
		return "E-RABToBeSetupItemBearerSUReqExtIEs"
	case "ERABToBeSetupItemCtxtSUReqExtIEs":
		return "E-RABToBeSetupItemCtxtSUReqExtIEs"
	case "ERABToBeSetupItemHOReqExtIEs":
		return "E-RABToBeSetupItemHOReq-ExtIEs"
	case "ERABToBeSwitchedDLItemExtIEs":
		return "E-RABToBeSwitchedDLItem-ExtIEs"
	case "GBR-QosInformation-ExtIEs":
		return "GBR-QosInformation-ExtIEs"
	case "GBRQosInformationExtIEs":
		return "GBR-QosInformation-ExtIEs"
	case "HandoverRestrictionList-ExtIEs":
		return "HandoverRestrictionList-ExtIEs"
	case "HandoverRestrictionListExtIEs":
		return "HandoverRestrictionList-ExtIEs"
	case "ImmediateMDT-ExtIEs":
		return "ImmediateMDT-ExtIEs"
	case "ImmediateMDTExtIEs":
		return "ImmediateMDT-ExtIEs"
	case "LastVisitedEUTRANCellInformation-ExtIEs":
		return "LastVisitedEUTRANCellInformation-ExtIEs"
	case "LastVisitedEUTRANCellInformationExtIEs":
		return "LastVisitedEUTRANCellInformation-ExtIEs"
	case "LoggedMDT-ExtIEs":
		return "LoggedMDT-ExtIEs"
	case "LoggedMDTExtIEs":
		return "LoggedMDT-ExtIEs"
	case "M4Configuration-ExtIEs":
		return "M4Configuration-ExtIEs"
	case "M4ConfigurationExtIEs":
		return "M4Configuration-ExtIEs"
	case "M5Configuration-ExtIEs":
		return "M5Configuration-ExtIEs"
	case "M5ConfigurationExtIEs":
		return "M5Configuration-ExtIEs"
	case "M6Configuration-ExtIEs":
		return "M6Configuration-ExtIEs"
	case "M6ConfigurationExtIEs":
		return "M6Configuration-ExtIEs"
	case "M7Configuration-ExtIEs":
		return "M7Configuration-ExtIEs"
	case "M7ConfigurationExtIEs":
		return "M7Configuration-ExtIEs"
	case "MDT-Configuration-ExtIEs":
		return "MDT-Configuration-ExtIEs"
	case "MDTConfigurationExtIEs":
		return "MDT-Configuration-ExtIEs"
	case "ProSeAuthorized-ExtIEs":
		return "ProSeAuthorized-ExtIEs"
	case "ProSeAuthorizedExtIEs":
		return "ProSeAuthorized-ExtIEs"
	case "RLFReportInformation-ExtIEs":
		return "RLFReportInformation-ExtIEs"
	case "RLFReportInformationExtIEs":
		return "RLFReportInformation-ExtIEs"
	case "RequestType-ExtIEs":
		return "RequestType-ExtIEs"
	case "RequestTypeExtIEs":
		return "RequestType-ExtIEs"
	case "SONConfigurationTransfer-ExtIEs":
		return "SONConfigurationTransfer-ExtIEs"
	case "SONConfigurationTransferExtIEs":
		return "SONConfigurationTransfer-ExtIEs"
	case "SONInformationReply-ExtIEs":
		return "SONInformationReply-ExtIEs"
	case "SONInformationReplyExtIEs":
		return "SONInformationReply-ExtIEs"
	case "ServedGUMMEIsItem-ExtIEs":
		return "ServedGUMMEIsItem-ExtIEs"
	case "ServedGUMMEIsItemExtIEs":
		return "ServedGUMMEIsItem-ExtIEs"
	case "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs":
		return "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs"
	case "SourceeNBToTargeteNBTransparentContainerExtIEs":
		return "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs"
	case "SupportedTAs-Item-ExtIEs":
		return "SupportedTAs-Item-ExtIEs"
	case "SupportedTAsItemExtIEs":
		return "SupportedTAs-Item-ExtIEs"
	case "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs":
		return "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs"
	case "TargeteNBToSourceeNBTransparentContainerExtIEs":
		return "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs"
	case "TimeSynchronisationInfo-ExtIEs":
		return "TimeSynchronisationInfo-ExtIEs"
	case "TimeSynchronisationInfoExtIEs":
		return "TimeSynchronisationInfo-ExtIEs"
	case "TraceActivation-ExtIEs":
		return "TraceActivation-ExtIEs"
	case "TraceActivationExtIEs":
		return "TraceActivation-ExtIEs"
	case "UEAggregate-MaximumBitrates-ExtIEs":
		return "UEAggregate-MaximumBitrates-ExtIEs"
	case "UEAggregateMaximumBitratesExtIEs":
		return "UEAggregate-MaximumBitrates-ExtIEs"
	case "UEAppLayerMeasConfig-ExtIEs":
		return "UEAppLayerMeasConfig-ExtIEs"
	case "UEAppLayerMeasConfigExtIEs":
		return "UEAppLayerMeasConfig-ExtIEs"
	case "UserLocationInformation-ExtIEs":
		return "UserLocationInformation-ExtIEs"
	case "UserLocationInformationExtIEs":
		return "UserLocationInformation-ExtIEs"
	case "X2TNLConfigurationInfo-ExtIEs":
		return "X2TNLConfigurationInfo-ExtIEs"
	case "X2TNLConfigurationInfoExtIEs":
		return "X2TNLConfigurationInfo-ExtIEs"
	default:
		return context
	}
}

func protocolIEValueTypeHint(objectSet string, id int64) protocolOpenTypeHint {
	switch objectSet {
	case "DownlinkS1cdma2000tunnellingIEs":
		switch id {
		case 12:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABDataForwardingItemIEs", typeName: "ERABSubjecttoDataForwardingList"}
		}
	case "E-RABModificationConfirmIEs":
		switch id {
		case 203:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABModifyItemBearerModConfIEs", typeName: "ERABModifyListBearerModConf"}
		case 205:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABItemIEs", typeName: "ERABList"}
		case 210:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABItemIEs", typeName: "ERABList"}
		}
	case "E-RABModificationIndicationIEs":
		switch id {
		case 199:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABToBeModifiedItemBearerModIndIEs", typeName: "ERABToBeModifiedListBearerModInd"}
		case 201:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABNotToBeModifiedItemBearerModIndIEs", typeName: "ERABNotToBeModifiedListBearerModInd"}
		case 264:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "SecondaryRATDataUsageReportItemIEs", typeName: "SecondaryRATDataUsageReportList"}
		}
	case "E-RABModifyRequestIEs":
		switch id {
		case 30:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABToBeModifiedItemBearerModReqIEs", typeName: "ERABToBeModifiedListBearerModReq"}
		}
	case "E-RABModifyResponseIEs":
		switch id {
		case 31:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABModifyItemBearerModResIEs", typeName: "ERABModifyListBearerModRes"}
		case 32:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABItemIEs", typeName: "ERABList"}
		case 264:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "SecondaryRATDataUsageReportItemIEs", typeName: "SecondaryRATDataUsageReportList"}
		}
	case "E-RABReleaseCommandIEs":
		switch id {
		case 33:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABItemIEs", typeName: "ERABList"}
		}
	case "E-RABReleaseIndicationIEs":
		switch id {
		case 110:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABItemIEs", typeName: "ERABList"}
		case 264:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "SecondaryRATDataUsageReportItemIEs", typeName: "SecondaryRATDataUsageReportList"}
		}
	case "E-RABReleaseResponseIEs":
		switch id {
		case 34:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABItemIEs", typeName: "ERABList"}
		case 69:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABReleaseItemBearerRelCompIEs", typeName: "ERABReleaseListBearerRelComp"}
		case 264:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "SecondaryRATDataUsageReportItemIEs", typeName: "SecondaryRATDataUsageReportList"}
		}
	case "E-RABSetupRequestIEs":
		switch id {
		case 16:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABToBeSetupItemBearerSUReqIEs", typeName: "ERABToBeSetupListBearerSUReq"}
		}
	case "E-RABSetupResponseIEs":
		switch id {
		case 28:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABSetupItemBearerSUResIEs", typeName: "ERABSetupListBearerSURes"}
		case 29:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABItemIEs", typeName: "ERABList"}
		}
	case "HandoverCommandIEs":
		switch id {
		case 12:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABDataForwardingItemIEs", typeName: "ERABSubjecttoDataForwardingList"}
		case 13:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABItemIEs", typeName: "ERABList"}
		}
	case "HandoverRequestAcknowledgeIEs":
		switch id {
		case 18:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABAdmittedItemIEs", typeName: "ERABAdmittedList"}
		case 19:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABFailedtoSetupItemHOReqAckIEs", typeName: "ERABFailedtoSetupListHOReqAck"}
		}
	case "HandoverRequestIEs":
		switch id {
		case 53:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABToBeSetupItemHOReqIEs", typeName: "ERABToBeSetupListHOReq"}
		}
	case "InitialContextSetupRequestIEs":
		switch id {
		case 24:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABToBeSetupItemCtxtSUReqIEs", typeName: "ERABToBeSetupListCtxtSUReq"}
		}
	case "InitialContextSetupResponseIEs":
		switch id {
		case 48:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABItemIEs", typeName: "ERABList"}
		case 51:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABSetupItemCtxtSUResIEs", typeName: "ERABSetupListCtxtSURes"}
		}
	case "PagingIEs":
		switch id {
		case 46:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "TAIItemIEs", typeName: "TAIList"}
		}
	case "PathSwitchRequestAcknowledgeIEs":
		switch id {
		case 33:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABItemIEs", typeName: "ERABList"}
		case 95:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABToBeSwitchedULItemIEs", typeName: "ERABToBeSwitchedULList"}
		case 341:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABToBeUpdatedItemIEs", typeName: "ERABToBeUpdatedList"}
		}
	case "PathSwitchRequestIEs":
		switch id {
		case 22:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABToBeSwitchedDLItemIEs", typeName: "ERABToBeSwitchedDLList"}
		}
	case "ResetAcknowledgeIEs":
		switch id {
		case 93:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "UE-associatedLogicalS1-ConnectionItemResAck", typeName: "UEAssociatedLogicalS1ConnectionListResAck"}
		}
	case "SecondaryRATDataUsageReportIEs":
		switch id {
		case 264:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "SecondaryRATDataUsageReportItemIEs", typeName: "SecondaryRATDataUsageReportList"}
		}
	case "UEContextReleaseComplete-IEs":
		switch id {
		case 264:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "SecondaryRATDataUsageReportItemIEs", typeName: "SecondaryRATDataUsageReportList"}
		}
	case "UEContextReleaseRequest-IEs":
		switch id {
		case 264:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "SecondaryRATDataUsageReportItemIEs", typeName: "SecondaryRATDataUsageReportList"}
		}
	case "UEContextResumeRequestIEs":
		switch id {
		case 235:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABFailedToResumeItemResumeReqIEs", typeName: "ERABFailedToResumeListResumeReq"}
		}
	case "UEContextResumeResponseIEs":
		switch id {
		case 237:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABFailedToResumeItemResumeResIEs", typeName: "ERABFailedToResumeListResumeRes"}
		}
	case "UEContextSuspendRequestIEs":
		switch id {
		case 264:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "SecondaryRATDataUsageReportItemIEs", typeName: "SecondaryRATDataUsageReportList"}
		}
	}
	return protocolOpenTypeHint{}
}

func protocolExtensionValueTypeHint(objectSet string, id int64) protocolOpenTypeHint {
	switch objectSet {
	case "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs":
		switch id {
		case 318:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "DAPSResponseInfoListIEs", typeName: "DAPSResponseInfoList"}
		case 335:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABSecurityResultListIEs", typeName: "ERABSecurityResultList"}
		}
	}
	return protocolOpenTypeHint{}
}

type protocolOpenTypeHint struct {
	family    string
	objectSet string
	typeName  string
}

type decodedProtocolFields struct {
	protocolIEs []DecodedProtocolIEField
	extensions  []DecodedProtocolExtensionField
}

// DecodeProtocolIEFieldsRecursive decodes fields using an ASN.1 object-set or legacy message-type context.
func DecodeProtocolIEFieldsRecursive(context string, fields []ProtocolIEField) ([]DecodedProtocolIEField, error) {
	objectSet := protocolIEObjectSet(context)
	return decodeProtocolIEFieldsAt(objectSet, fields, objectSet, map[protocolOpenTypeVisit]bool{})
}

// DecodeProtocolExtensionFieldsRecursive decodes extension fields using their ASN.1 object-set context.
func DecodeProtocolExtensionFieldsRecursive(context string, fields []ProtocolExtensionField) ([]DecodedProtocolExtensionField, error) {
	objectSet := protocolExtensionObjectSet(context)
	return decodeProtocolExtensionFieldsAt(objectSet, fields, objectSet, map[protocolOpenTypeVisit]bool{})
}

// DecodeProtocolIEsRecursive discovers and decodes every context-bound ProtocolIE-Field list in value.
func DecodeProtocolIEsRecursive(value interface{}) ([]DecodedProtocolIEField, error) {
	fields, err := decodeProtocolFieldsRecursive(value)
	if err != nil {
		return nil, err
	}
	return fields.protocolIEs, nil
}

// DecodeProtocolExtensionsRecursive discovers and decodes every context-bound ProtocolExtensionField list in value.
func DecodeProtocolExtensionsRecursive(value interface{}) ([]DecodedProtocolExtensionField, error) {
	fields, err := decodeProtocolFieldsRecursive(value)
	if err != nil {
		return nil, err
	}
	return fields.extensions, nil
}

func decodeProtocolFieldsRecursive(value interface{}) (decodedProtocolFields, error) {
	if value == nil {
		return decodedProtocolFields{}, nil
	}
	rv := reflect.ValueOf(value)
	root := indirectProtocolOpenTypeValue(rv)
	if !root.IsValid() {
		return decodedProtocolFields{}, nil
	}
	path := root.Type().Name()
	if path == "" {
		return decodedProtocolFields{}, fmt.Errorf("recursive protocol open-type decode requires a named root value; use a field-list function for a standalone list")
	}
	return decodeProtocolFieldsInValue(rv, protocolOpenTypeHint{}, path, map[protocolOpenTypeVisit]bool{})
}

type protocolOpenTypeVisit struct {
	typ reflect.Type
	ptr uintptr
}

func indirectProtocolOpenTypeValue(value reflect.Value) reflect.Value {
	for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		if value.IsNil() {
			return reflect.Value{}
		}
		value = value.Elem()
	}
	return value
}

func decodeProtocolFieldsInValue(value reflect.Value, hint protocolOpenTypeHint, path string, seen map[protocolOpenTypeVisit]bool) (decodedProtocolFields, error) {
	for value.IsValid() && value.Kind() == reflect.Interface {
		if value.IsNil() {
			return decodedProtocolFields{}, nil
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return decodedProtocolFields{}, nil
	}
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return decodedProtocolFields{}, nil
		}
		visit := protocolOpenTypeVisit{typ: value.Type(), ptr: value.Pointer()}
		if seen[visit] {
			return decodedProtocolFields{}, nil
		}
		seen[visit] = true
		defer delete(seen, visit)
		return decodeProtocolFieldsInValue(value.Elem(), hint, path, seen)
	}

	resolvedType := hint.typeName
	if resolvedType == "" {
		resolvedType = value.Type().Name()
	}
	if hint.objectSet != "" {
		switch hint.family {
		case "protocolIE":
			fields, ok := protocolIEFieldsFromValue(value)
			if !ok {
				return decodedProtocolFields{}, fmt.Errorf("%s: generated binding %s expects ProtocolIE-Field data, got %s", path, resolvedType, value.Type())
			}
			decoded, err := decodeProtocolIEFieldsAt(hint.objectSet, fields, path, seen)
			return decodedProtocolFields{protocolIEs: decoded}, err
		case "protocolExtension":
			fields, ok := protocolExtensionFieldsFromValue(value)
			if !ok {
				return decodedProtocolFields{}, fmt.Errorf("%s: generated binding %s expects ProtocolExtensionField data, got %s", path, resolvedType, value.Type())
			}
			decoded, err := decodeProtocolExtensionFieldsAt(hint.objectSet, fields, path, seen)
			return decodedProtocolFields{extensions: decoded}, err
		}
	}
	if objectSet := protocolIETypeObjectSets[resolvedType]; objectSet != "" {
		fields, ok := protocolIEFieldsFromValue(value)
		if !ok {
			return decodedProtocolFields{}, fmt.Errorf("%s: generated binding %s expects ProtocolIE-Field data, got %s", path, resolvedType, value.Type())
		}
		decoded, err := decodeProtocolIEFieldsAt(objectSet, fields, path, seen)
		return decodedProtocolFields{protocolIEs: decoded}, err
	}
	if objectSet := protocolExtensionTypeObjectSets[resolvedType]; objectSet != "" {
		fields, ok := protocolExtensionFieldsFromValue(value)
		if !ok {
			return decodedProtocolFields{}, fmt.Errorf("%s: generated binding %s expects ProtocolExtensionField data, got %s", path, resolvedType, value.Type())
		}
		decoded, err := decodeProtocolExtensionFieldsAt(objectSet, fields, path, seen)
		return decodedProtocolFields{extensions: decoded}, err
	}

	switch value.Kind() {
	case reflect.Struct:
		owner := value.Type().Name()
		var result decodedProtocolFields
		for i := 0; i < value.NumField(); i++ {
			fieldInfo := value.Type().Field(i)
			if fieldInfo.PkgPath != "" || fieldInfo.Tag.Get("asn1") == "-" {
				continue
			}
			fieldPath := path + "." + fieldInfo.Name
			fieldValue := value.Field(i)
			if objectSet := protocolIEFieldObjectSets[owner+"."+fieldInfo.Name]; objectSet != "" {
				fields, ok := protocolIEFieldsFromValue(fieldValue)
				if !ok {
					return decodedProtocolFields{}, fmt.Errorf("%s: generated binding expects ProtocolIE-Field data, got %s", fieldPath, fieldValue.Type())
				}
				decoded, err := decodeProtocolIEFieldsAt(objectSet, fields, fieldPath, seen)
				if err != nil {
					return decodedProtocolFields{}, err
				}
				result.protocolIEs = append(result.protocolIEs, decoded...)
				continue
			}
			if objectSet := protocolExtensionFieldObjectSets[owner+"."+fieldInfo.Name]; objectSet != "" {
				fields, ok := protocolExtensionFieldsFromValue(fieldValue)
				if !ok {
					return decodedProtocolFields{}, fmt.Errorf("%s: generated binding expects ProtocolExtensionField data, got %s", fieldPath, fieldValue.Type())
				}
				decoded, err := decodeProtocolExtensionFieldsAt(objectSet, fields, fieldPath, seen)
				if err != nil {
					return decodedProtocolFields{}, err
				}
				result.extensions = append(result.extensions, decoded...)
				continue
			}
			decoded, err := decodeProtocolFieldsInValue(fieldValue, protocolOpenTypeHint{}, fieldPath, seen)
			if err != nil {
				return decodedProtocolFields{}, err
			}
			result.protocolIEs = append(result.protocolIEs, decoded.protocolIEs...)
			result.extensions = append(result.extensions, decoded.extensions...)
		}
		return result, nil
	case reflect.Slice, reflect.Array:
		var result decodedProtocolFields
		for i := 0; i < value.Len(); i++ {
			decoded, err := decodeProtocolFieldsInValue(value.Index(i), protocolOpenTypeHint{}, fmt.Sprintf("%s[%d]", path, i), seen)
			if err != nil {
				return decodedProtocolFields{}, err
			}
			result.protocolIEs = append(result.protocolIEs, decoded.protocolIEs...)
			result.extensions = append(result.extensions, decoded.extensions...)
		}
		return result, nil
	default:
		return decodedProtocolFields{}, nil
	}
}

func protocolIEFieldsFromValue(value reflect.Value) ([]ProtocolIEField, bool) {
	value = indirectProtocolOpenTypeValue(value)
	if !value.IsValid() {
		return nil, true
	}
	fieldType := reflect.TypeOf(ProtocolIEField{})
	if value.Type() == fieldType || value.Type().ConvertibleTo(fieldType) {
		return []ProtocolIEField{value.Convert(fieldType).Interface().(ProtocolIEField)}, true
	}
	if value.Kind() != reflect.Slice && value.Kind() != reflect.Array {
		return nil, false
	}
	result := make([]ProtocolIEField, value.Len())
	for i := 0; i < value.Len(); i++ {
		item := indirectProtocolOpenTypeValue(value.Index(i))
		if !item.IsValid() || !item.Type().ConvertibleTo(fieldType) {
			return nil, false
		}
		result[i] = item.Convert(fieldType).Interface().(ProtocolIEField)
	}
	return result, true
}

func protocolExtensionFieldsFromValue(value reflect.Value) ([]ProtocolExtensionField, bool) {
	value = indirectProtocolOpenTypeValue(value)
	if !value.IsValid() {
		return nil, true
	}
	fieldType := reflect.TypeOf(ProtocolExtensionField{})
	if value.Type() == fieldType || value.Type().ConvertibleTo(fieldType) {
		return []ProtocolExtensionField{value.Convert(fieldType).Interface().(ProtocolExtensionField)}, true
	}
	if value.Kind() != reflect.Slice && value.Kind() != reflect.Array {
		return nil, false
	}
	result := make([]ProtocolExtensionField, value.Len())
	for i := 0; i < value.Len(); i++ {
		item := indirectProtocolOpenTypeValue(value.Index(i))
		if !item.IsValid() || !item.Type().ConvertibleTo(fieldType) {
			return nil, false
		}
		result[i] = item.Convert(fieldType).Interface().(ProtocolExtensionField)
	}
	return result, true
}

func decodeProtocolIEFieldsAt(objectSet string, fields []ProtocolIEField, path string, seen map[protocolOpenTypeVisit]bool) ([]DecodedProtocolIEField, error) {
	result := make([]DecodedProtocolIEField, len(fields))
	for i := range fields {
		fieldPath := fmt.Sprintf("%s[%d]", path, i)
		result[i] = DecodedProtocolIEField{Path: fieldPath, ObjectSet: objectSet, Field: fields[i]}
		value, err := DecodeIEFieldValue(objectSet, int64(fields[i].Id), fields[i].Value.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: decoding object set %s IE %d: %w", fieldPath, objectSet, fields[i].Id, err)
		}
		result[i].Value = value
		if value == nil {
			continue
		}
		children, err := decodeProtocolFieldsInValue(reflect.ValueOf(value), protocolIEValueTypeHint(objectSet, int64(fields[i].Id)), fieldPath, seen)
		if err != nil {
			return nil, err
		}
		result[i].Children = children.protocolIEs
		result[i].Extensions = children.extensions
	}
	return result, nil
}

func decodeProtocolExtensionFieldsAt(objectSet string, fields []ProtocolExtensionField, path string, seen map[protocolOpenTypeVisit]bool) ([]DecodedProtocolExtensionField, error) {
	result := make([]DecodedProtocolExtensionField, len(fields))
	for i := range fields {
		fieldPath := fmt.Sprintf("%s[%d]", path, i)
		result[i] = DecodedProtocolExtensionField{Path: fieldPath, ObjectSet: objectSet, Field: fields[i]}
		value, err := DecodeExtensionFieldValue(objectSet, int64(fields[i].Id), fields[i].ExtensionValue.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: decoding object set %s extension %d: %w", fieldPath, objectSet, fields[i].Id, err)
		}
		result[i].Value = value
		if value == nil {
			continue
		}
		children, err := decodeProtocolFieldsInValue(reflect.ValueOf(value), protocolExtensionValueTypeHint(objectSet, int64(fields[i].Id)), fieldPath, seen)
		if err != nil {
			return nil, err
		}
		result[i].ProtocolIEs = children.protocolIEs
		result[i].Extensions = children.extensions
	}
	return result, nil
}

// DecodeValueRecursive decodes InitiatingMessage and every nested protocol IE and extension with ASN.1 object-set context.
func (v *InitiatingMessage) DecodeValueRecursive() (*DecodedProtocolValue, error) {
	value, err := v.DecodeValue()
	if err != nil {
		return nil, err
	}
	fields, err := decodeProtocolFieldsRecursive(value)
	if err != nil {
		return nil, err
	}
	return &DecodedProtocolValue{Value: value, ProtocolIEs: fields.protocolIEs, ProtocolExtensions: fields.extensions}, nil
}

// DecodeValueRecursive decodes SuccessfulOutcome and every nested protocol IE and extension with ASN.1 object-set context.
func (v *SuccessfulOutcome) DecodeValueRecursive() (*DecodedProtocolValue, error) {
	value, err := v.DecodeValue()
	if err != nil {
		return nil, err
	}
	fields, err := decodeProtocolFieldsRecursive(value)
	if err != nil {
		return nil, err
	}
	return &DecodedProtocolValue{Value: value, ProtocolIEs: fields.protocolIEs, ProtocolExtensions: fields.extensions}, nil
}

// DecodeValueRecursive decodes UnsuccessfulOutcome and every nested protocol IE and extension with ASN.1 object-set context.
func (v *UnsuccessfulOutcome) DecodeValueRecursive() (*DecodedProtocolValue, error) {
	value, err := v.DecodeValue()
	if err != nil {
		return nil, err
	}
	fields, err := decodeProtocolFieldsRecursive(value)
	if err != nil {
		return nil, err
	}
	return &DecodedProtocolValue{Value: value, ProtocolIEs: fields.protocolIEs, ProtocolExtensions: fields.extensions}, nil
}

// DecodeValue decodes the Value field of InitiatingMessage based on ProcedureCode.
// Returns the decoded typed struct (e.g., *HandoverRequired), or nil if unknown.
func (v *InitiatingMessage) DecodeValue() (interface{}, error) {
	return DecodeInitiatingMessageValue(v.ProcedureCode, v.Value.Bytes)
}

// DecodeValue decodes the Value field of SuccessfulOutcome based on ProcedureCode.
// Returns the decoded typed struct (e.g., *HandoverRequired), or nil if unknown.
func (v *SuccessfulOutcome) DecodeValue() (interface{}, error) {
	return DecodeSuccessfulOutcomeValue(v.ProcedureCode, v.Value.Bytes)
}

// DecodeValue decodes the Value field of UnsuccessfulOutcome based on ProcedureCode.
// Returns the decoded typed struct (e.g., *HandoverRequired), or nil if unknown.
func (v *UnsuccessfulOutcome) DecodeValue() (interface{}, error) {
	return DecodeUnsuccessfulOutcomeValue(v.ProcedureCode, v.Value.Bytes)
}

// DecodeValue decodes the Value field of a ProtocolIE-Field based on message type and IE ID.
// messageType should be the Go type name (e.g., "HandoverRequired").
func (v *ProtocolIEField) DecodeValue(messageType string) (interface{}, error) {
	return DecodeIEFieldValue(messageType, int64(v.Id), v.Value.Bytes)
}

// DecodeValue decodes ExtensionValue based on its object-set context and extension ID.
func (v *ProtocolExtensionField) DecodeValue(context string) (interface{}, error) {
	return DecodeExtensionFieldValue(context, int64(v.Id), v.ExtensionValue.Bytes)
}
