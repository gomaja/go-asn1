// Code generated from ASN.1. DO NOT EDIT.

package s1ap

import (
	"fmt"
	"reflect"

	"github.com/gomaja/go-asn1/runtime"
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
	case 67: // id-S1Removal
		var v S1RemovalRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding S1RemovalRequest: %w", err)
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
	case 67: // id-S1Removal
		var v S1RemovalResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding S1RemovalResponse: %w", err)
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
	case 67: // id-S1Removal
		var v S1RemovalFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding S1RemovalFailure: %w", err)
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
	result := make([]ProtocolIEField, 0)
	for i := int64(0); i < n; i++ {
		var item ProtocolIEField
		if err := item.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding item %d: %w", i, err)
		}
		result = append(result, item)
	}
	return result, nil
}

// DecodeIEFieldValue decodes a known IE open value using its object-set context and ID.
// Returns the decoded typed value, or nil if the combination is unknown.
func DecodeIEFieldValue(objectSet string, ieId int64, data []byte) (interface{}, error) {
	bb := per.NewBitBufferFromBytes(data)
	switch objectSet {
	case "Bearers-SubjectToStatusTransfer-ItemIEs":
		switch ieId {
		case 89: // id-Bearers-SubjectToStatusTransfer-Item -> BearersSubjectToStatusTransferItem
			var v BearersSubjectToStatusTransferItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE BearersSubjectToStatusTransferItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "Bearers-SubjectToEarlyStatusTransfer-ItemIEs":
		switch ieId {
		case 322: // id-Bearers-SubjectToEarlyStatusTransfer-Item -> BearersSubjectToEarlyStatusTransferItem
			var v BearersSubjectToEarlyStatusTransferItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE BearersSubjectToEarlyStatusTransferItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "Bearers-SubjectToDLDiscarding-ItemIEs":
		switch ieId {
		case 351: // id-Bearers-SubjectToDLDiscarding-Item -> BearersSubjectToDLDiscardingItem
			var v BearersSubjectToDLDiscardingItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE BearersSubjectToDLDiscardingItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "DAPSResponseInfoListIEs":
		switch ieId {
		case 319: // id-DAPSResponseInfoItem -> DAPSResponseInfoItem
			var v DAPSResponseInfoItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE DAPSResponseInfoItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABInformationListIEs":
		switch ieId {
		case 78: // id-E-RABInformationListItem -> ERABInformationListItem
			var v ERABInformationListItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABInformationListItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABItemIEs":
		switch ieId {
		case 35: // id-E-RABItem -> ERABItem
			var v ERABItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABSecurityResultListIEs":
		switch ieId {
		case 334: // id-E-RABSecurityResultItem -> ERABSecurityResultItem
			var v ERABSecurityResultItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABSecurityResultItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABUsageReportItemIEs":
		switch ieId {
		case 267: // id-E-RABUsageReportItem -> ERABUsageReportItem
			var v ERABUsageReportItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABUsageReportItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MDTMode-ExtensionIE":
		switch ieId {
		case 197: // id-LoggedMBSFNMDT -> LoggedMBSFNMDT
			var v LoggedMBSFNMDT
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LoggedMBSFNMDT (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "RecommendedCellItemIEs":
		switch ieId {
		case 214: // id-RecommendedCellItem -> RecommendedCellItem
			var v RecommendedCellItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RecommendedCellItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "RecommendedENBItemIEs":
		switch ieId {
		case 215: // id-RecommendedENBItem -> RecommendedENBItem
			var v RecommendedENBItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RecommendedENBItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SecondaryRATDataUsageReportItemIEs":
		switch ieId {
		case 265: // id-SecondaryRATDataUsageReportItem -> SecondaryRATDataUsageReportItem
			var v SecondaryRATDataUsageReportItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SecondaryRATDataUsageReportItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SONInformation-ExtensionIE":
		switch ieId {
		case 206: // id-SON-Information-Report -> SONInformationReport
			var v SONInformationReport
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SONInformationReport (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverRequiredIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
		case 79: // id-Direct-Forwarding-Path-Availability -> DirectForwardingPathAvailability (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE DirectForwardingPathAvailability (%d): %w", ieId, err)
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
		case 104: // id-Source-ToTarget-TransparentContainer -> SourceToTargetTransparentContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SourceToTargetTransparentContainer (%d): %w", ieId, err)
			}
			result := SourceToTargetTransparentContainer(v)
			return &result, nil
		case 138: // id-Source-ToTarget-TransparentContainer-Secondary -> SourceToTargetTransparentContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SourceToTargetTransparentContainer (%d): %w", ieId, err)
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
		case 127: // id-CSG-Id -> CSGId (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 27, 27, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGId (%d): %w", ieId, err)
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
		case 150: // id-PS-ServiceNotAvailable -> PSServiceNotAvailable (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PSServiceNotAvailable (%d): %w", ieId, err)
			}
			result := PSServiceNotAvailable(v)
			return &result, nil
		}
	case "HandoverCommandIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
		case 135: // id-NASSecurityParametersfromE-UTRAN -> NASSecurityParametersfromEUTRAN (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NASSecurityParametersfromEUTRAN (%d): %w", ieId, err)
			}
			result := NASSecurityParametersfromEUTRAN(v)
			return &result, nil
		case 12: // id-E-RABSubjecttoDataForwardingList -> ERABSubjecttoDataForwardingList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABSubjecttoDataForwardingList (%d): %w", ieId, err)
			}
			return &v, nil
		case 13: // id-E-RABtoReleaseListHOCmd -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 123: // id-Target-ToSource-TransparentContainer -> TargetToSourceTransparentContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TargetToSourceTransparentContainer (%d): %w", ieId, err)
			}
			result := TargetToSourceTransparentContainer(v)
			return &result, nil
		case 139: // id-Target-ToSource-TransparentContainer-Secondary -> TargetToSourceTransparentContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TargetToSourceTransparentContainer (%d): %w", ieId, err)
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
	case "E-RABDataForwardingItemIEs":
		switch ieId {
		case 14: // id-E-RABDataForwardingItem -> ERABDataForwardingItem
			var v ERABDataForwardingItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABDataForwardingItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverPreparationFailureIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "HandoverRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
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
		case 104: // id-Source-ToTarget-TransparentContainer -> SourceToTargetTransparentContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SourceToTargetTransparentContainer (%d): %w", ieId, err)
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
		case 136: // id-NASSecurityParameterstoE-UTRAN -> NASSecurityParameterstoEUTRAN (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NASSecurityParameterstoEUTRAN (%d): %w", ieId, err)
			}
			result := NASSecurityParameterstoEUTRAN(v)
			return &result, nil
		case 127: // id-CSG-Id -> CSGId (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 27, 27, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGId (%d): %w", ieId, err)
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
		case 158: // id-MME-UE-S1AP-ID-2 -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
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
		case 177: // id-ManagementBasedMDTPLMNList -> MDTPLMNList (SEQUENCE_OF)
			v, err := UnmarshalAPERMDTPLMNListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MDTPLMNList (%d): %w", ieId, err)
			}
			return &v, nil
		case 192: // id-Masked-IMEISV -> MaskedIMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MaskedIMEISV (%d): %w", ieId, err)
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
		case 271: // id-CE-ModeBRestricted -> CEModeBRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CEModeBRestricted (%d): %w", ieId, err)
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
		case 278: // id-Subscription-Based-UE-DifferentiationInfo -> SubscriptionBasedUEDifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SubscriptionBasedUEDifferentiationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 299: // id-AdditionalRRMPriorityIndex -> AdditionalRRMPriorityIndex (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AdditionalRRMPriorityIndex (%d): %w", ieId, err)
			}
			result := AdditionalRRMPriorityIndex{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 301: // id-IAB-Authorized -> IABAuthorized (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IABAuthorized (%d): %w", ieId, err)
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
		case 355: // id-TimeRefDistribution -> TimeRefDistribution (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeRefDistribution (%d): %w", ieId, err)
			}
			result := TimeRefDistribution(v)
			return &result, nil
		}
	case "E-RABToBeSetupItemHOReqIEs":
		switch ieId {
		case 27: // id-E-RABToBeSetupItemHOReq -> ERABToBeSetupItemHOReq
			var v ERABToBeSetupItemHOReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSetupItemHOReq (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverRequestAcknowledgeIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
		case 123: // id-Target-ToSource-TransparentContainer -> TargetToSourceTransparentContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TargetToSourceTransparentContainer (%d): %w", ieId, err)
			}
			result := TargetToSourceTransparentContainer(v)
			return &result, nil
		case 127: // id-CSG-Id -> CSGId (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 27, 27, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGId (%d): %w", ieId, err)
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
		case 242: // id-CE-mode-B-SupportIndicator -> CEModeBSupportIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CEModeBSupportIndicator (%d): %w", ieId, err)
			}
			result := CEModeBSupportIndicator(v)
			return &result, nil
		}
	case "E-RABAdmittedItemIEs":
		switch ieId {
		case 20: // id-E-RABAdmittedItem -> ERABAdmittedItem
			var v ERABAdmittedItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABAdmittedItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABFailedtoSetupItemHOReqAckIEs":
		switch ieId {
		case 21: // id-E-RABFailedtoSetupItemHOReqAck -> ERABFailedToSetupItemHOReqAck
			var v ERABFailedToSetupItemHOReqAck
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABFailedToSetupItemHOReqAck (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverFailureIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
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
	case "HandoverNotifyIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 100: // id-EUTRAN-CGI -> EUTRANCGI
			var v EUTRANCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EUTRANCGI (%d): %w", ieId, err)
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
		case 186: // id-LHN-ID -> LHNID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 32, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LHNID (%d): %w", ieId, err)
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
		case 339: // id-LTE-NTN-TAI-Information -> LTENTNTAIInformation
			var v LTENTNTAIInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LTENTNTAIInformation (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "PathSwitchRequestIEs":
		switch ieId {
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 22: // id-E-RABToBeSwitchedDLList -> ERABToBeSwitchedDLList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSwitchedDLList (%d): %w", ieId, err)
			}
			return &v, nil
		case 88: // id-SourceMME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 100: // id-EUTRAN-CGI -> EUTRANCGI
			var v EUTRANCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EUTRANCGI (%d): %w", ieId, err)
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
		case 127: // id-CSG-Id -> CSGId (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 27, 27, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGId (%d): %w", ieId, err)
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
		case 186: // id-LHN-ID -> LHNID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 32, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LHNID (%d): %w", ieId, err)
			}
			result := LHNID(v)
			return &result, nil
		case 245: // id-RRC-Resume-Cause -> RRCEstablishmentCause (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 5, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RRCEstablishmentCause (%d): %w", ieId, err)
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
		case 339: // id-LTE-NTN-TAI-Information -> LTENTNTAIInformation
			var v LTENTNTAIInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LTENTNTAIInformation (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABToBeSwitchedDLItemIEs":
		switch ieId {
		case 23: // id-E-RABToBeSwitchedDLItem -> ERABToBeSwitchedDLItem
			var v ERABToBeSwitchedDLItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSwitchedDLItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "PathSwitchRequestAcknowledgeIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
		case 33: // id-E-RABToBeReleasedList -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
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
		case 158: // id-MME-UE-S1AP-ID-2 -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
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
		case 271: // id-CE-ModeBRestricted -> CEModeBRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CEModeBRestricted (%d): %w", ieId, err)
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
		case 278: // id-Subscription-Based-UE-DifferentiationInfo -> SubscriptionBasedUEDifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SubscriptionBasedUEDifferentiationInfo (%d): %w", ieId, err)
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
		case 355: // id-TimeRefDistribution -> TimeRefDistribution (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeRefDistribution (%d): %w", ieId, err)
			}
			result := TimeRefDistribution(v)
			return &result, nil
		}
	case "E-RABToBeSwitchedULItemIEs":
		switch ieId {
		case 94: // id-E-RABToBeSwitchedULItem -> ERABToBeSwitchedULItem
			var v ERABToBeSwitchedULItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSwitchedULItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABToBeUpdatedItemIEs":
		switch ieId {
		case 342: // id-E-RABToBeUpdatedItem -> ERABToBeUpdatedItem
			var v ERABToBeUpdatedItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeUpdatedItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "PathSwitchRequestFailureIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "HandoverCancelIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "HandoverCancelAcknowledgeIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "HandoverSuccessIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		}
	case "ENBEarlyStatusTransferIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 321: // id-eNB-EarlyStatusTransfer-TransparentContainer -> ENBEarlyStatusTransferTransparentContainer
			var v ENBEarlyStatusTransferTransparentContainer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ENBEarlyStatusTransferTransparentContainer (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MMEEarlyStatusTransferIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 321: // id-eNB-EarlyStatusTransfer-TransparentContainer -> ENBEarlyStatusTransferTransparentContainer
			var v ENBEarlyStatusTransferTransparentContainer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ENBEarlyStatusTransferTransparentContainer (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABSetupRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "E-RABToBeSetupItemBearerSUReqIEs":
		switch ieId {
		case 17: // id-E-RABToBeSetupItemBearerSUReq -> ERABToBeSetupItemBearerSUReq
			var v ERABToBeSetupItemBearerSUReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSetupItemBearerSUReq (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABSetupResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 28: // id-E-RABSetupListBearerSURes -> ERABSetupListBearerSURes (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABSetupListBearerSURes (%d): %w", ieId, err)
			}
			return &v, nil
		case 29: // id-E-RABFailedToSetupListBearerSURes -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
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
	case "E-RABSetupItemBearerSUResIEs":
		switch ieId {
		case 39: // id-E-RABSetupItemBearerSURes -> ERABSetupItemBearerSURes
			var v ERABSetupItemBearerSURes
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABSetupItemBearerSURes (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABModifyRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "E-RABToBeModifiedItemBearerModReqIEs":
		switch ieId {
		case 36: // id-E-RABToBeModifiedItemBearerModReq -> ERABToBeModifiedItemBearerModReq
			var v ERABToBeModifiedItemBearerModReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeModifiedItemBearerModReq (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABModifyResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 31: // id-E-RABModifyListBearerModRes -> ERABModifyListBearerModRes (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABModifyListBearerModRes (%d): %w", ieId, err)
			}
			return &v, nil
		case 32: // id-E-RABFailedToModifyList -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
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
	case "E-RABModifyItemBearerModResIEs":
		switch ieId {
		case 37: // id-E-RABModifyItemBearerModRes -> ERABModifyItemBearerModRes
			var v ERABModifyItemBearerModRes
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABModifyItemBearerModRes (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABReleaseCommandIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 66: // id-uEaggregateMaximumBitrate -> UEAggregateMaximumBitrate
			var v UEAggregateMaximumBitrate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEAggregateMaximumBitrate (%d): %w", ieId, err)
			}
			return &v, nil
		case 33: // id-E-RABToBeReleasedList -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 26: // id-NAS-PDU -> NASPDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NASPDU (%d): %w", ieId, err)
			}
			result := NASPDU(v)
			return &result, nil
		}
	case "E-RABReleaseResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 69: // id-E-RABReleaseListBearerRelComp -> ERABReleaseListBearerRelComp (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABReleaseListBearerRelComp (%d): %w", ieId, err)
			}
			return &v, nil
		case 34: // id-E-RABFailedToReleaseList -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
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
	case "E-RABReleaseItemBearerRelCompIEs":
		switch ieId {
		case 15: // id-E-RABReleaseItemBearerRelComp -> ERABReleaseItemBearerRelComp
			var v ERABReleaseItemBearerRelComp
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABReleaseItemBearerRelComp (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABReleaseIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 110: // id-E-RABReleasedList -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
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
	case "InitialContextSetupRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
		case 158: // id-MME-UE-S1AP-ID-2 -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
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
		case 177: // id-ManagementBasedMDTPLMNList -> MDTPLMNList (SEQUENCE_OF)
			v, err := UnmarshalAPERMDTPLMNListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MDTPLMNList (%d): %w", ieId, err)
			}
			return &v, nil
		case 187: // id-AdditionalCSFallbackIndicator -> AdditionalCSFallbackIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AdditionalCSFallbackIndicator (%d): %w", ieId, err)
			}
			result := AdditionalCSFallbackIndicator(v)
			return &result, nil
		case 192: // id-Masked-IMEISV -> MaskedIMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MaskedIMEISV (%d): %w", ieId, err)
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
		case 271: // id-CE-ModeBRestricted -> CEModeBRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CEModeBRestricted (%d): %w", ieId, err)
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
		case 278: // id-Subscription-Based-UE-DifferentiationInfo -> SubscriptionBasedUEDifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SubscriptionBasedUEDifferentiationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 299: // id-AdditionalRRMPriorityIndex -> AdditionalRRMPriorityIndex (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AdditionalRRMPriorityIndex (%d): %w", ieId, err)
			}
			result := AdditionalRRMPriorityIndex{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 301: // id-IAB-Authorized -> IABAuthorized (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IABAuthorized (%d): %w", ieId, err)
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
		case 354: // id-CoarseUELocation -> CoarseUELocation (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CoarseUELocation (%d): %w", ieId, err)
			}
			result := CoarseUELocation(v)
			return &result, nil
		case 355: // id-TimeRefDistribution -> TimeRefDistribution (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeRefDistribution (%d): %w", ieId, err)
			}
			result := TimeRefDistribution(v)
			return &result, nil
		}
	case "E-RABToBeSetupItemCtxtSUReqIEs":
		switch ieId {
		case 52: // id-E-RABToBeSetupItemCtxtSUReq -> ERABToBeSetupItemCtxtSUReq
			var v ERABToBeSetupItemCtxtSUReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeSetupItemCtxtSUReq (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "InitialContextSetupResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 51: // id-E-RABSetupListCtxtSURes -> ERABSetupListCtxtSURes (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABSetupListCtxtSURes (%d): %w", ieId, err)
			}
			return &v, nil
		case 48: // id-E-RABFailedToSetupListCtxtSURes -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABSetupItemCtxtSUResIEs":
		switch ieId {
		case 50: // id-E-RABSetupItemCtxtSURes -> ERABSetupItemCtxtSURes
			var v ERABSetupItemCtxtSURes
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABSetupItemCtxtSURes (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "InitialContextSetupFailureIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "PagingIEs":
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
		case 128: // id-CSG-IdList -> CSGIdList (SEQUENCE_OF)
			v, err := UnmarshalAPERCSGIdListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGIdList (%d): %w", ieId, err)
			}
			return &v, nil
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
		case 227: // id-Paging-eDRXInformation -> PagingEDRXInformation
			var v PagingEDRXInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE PagingEDRXInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 231: // id-extended-UEIdentityIndexValue -> ExtendedUEIdentityIndexValue (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 14, 14, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ExtendedUEIdentityIndexValue (%d): %w", ieId, err)
			}
			result := ExtendedUEIdentityIndexValue{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 239: // id-NB-IoT-Paging-eDRXInformation -> NBIoTPagingEDRXInformation
			var v NBIoTPagingEDRXInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NBIoTPagingEDRXInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 244: // id-NB-IoT-UEIdentityIndexValue -> NBIoTUEIdentityIndexValue (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 12, 12, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NBIoTUEIdentityIndexValue (%d): %w", ieId, err)
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
		case 271: // id-CE-ModeBRestricted -> CEModeBRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CEModeBRestricted (%d): %w", ieId, err)
			}
			result := CEModeBRestricted(v)
			return &result, nil
		case 304: // id-DataSize -> DataSize (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE DataSize (%d): %w", ieId, err)
			}
			return v, nil
		case 323: // id-WUS-Assistance-Information -> WUSAssistanceInformation
			var v WUSAssistanceInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE WUSAssistanceInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 324: // id-NB-IoT-PagingDRX -> NBIoTPagingDRX (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 6, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NBIoTPagingDRX (%d): %w", ieId, err)
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
	case "TAIItemIEs":
		switch ieId {
		case 47: // id-TAIItem -> TAIItem
			var v TAIItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TAIItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextReleaseRequest-IEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "UEContextReleaseCommand-IEs":
		switch ieId {
		case 99: // id-UE-S1AP-IDs -> UES1APIDs
			var v UES1APIDs
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UES1APIDs (%d): %w", ieId, err)
			}
			return &v, nil
		case 2: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextReleaseComplete-IEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "UEContextModificationRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
		case 301: // id-IAB-Authorized -> IABAuthorized (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IABAuthorized (%d): %w", ieId, err)
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
		case 355: // id-TimeRefDistribution -> TimeRefDistribution (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeRefDistribution (%d): %w", ieId, err)
			}
			result := TimeRefDistribution(v)
			return &result, nil
		}
	case "UEContextModificationResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "UEContextModificationFailureIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "UERadioCapabilityMatchRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "UERadioCapabilityMatchResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "DownlinkNASTransport-IEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 26: // id-NAS-PDU -> NASPDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NASPDU (%d): %w", ieId, err)
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
		case 271: // id-CE-ModeBRestricted -> CEModeBRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CEModeBRestricted (%d): %w", ieId, err)
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
		case 278: // id-Subscription-Based-UE-DifferentiationInfo -> SubscriptionBasedUEDifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SubscriptionBasedUEDifferentiationInfo (%d): %w", ieId, err)
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
		case 192: // id-Masked-IMEISV -> MaskedIMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MaskedIMEISV (%d): %w", ieId, err)
			}
			result := MaskedIMEISV{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 354: // id-CoarseUELocation -> CoarseUELocation (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CoarseUELocation (%d): %w", ieId, err)
			}
			result := CoarseUELocation(v)
			return &result, nil
		}
	case "InitialUEMessage-IEs":
		switch ieId {
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 26: // id-NAS-PDU -> NASPDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NASPDU (%d): %w", ieId, err)
			}
			result := NASPDU(v)
			return &result, nil
		case 67: // id-TAI -> TAI
			var v TAI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TAI (%d): %w", ieId, err)
			}
			return &v, nil
		case 100: // id-EUTRAN-CGI -> EUTRANCGI
			var v EUTRANCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EUTRANCGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 134: // id-RRC-Establishment-Cause -> RRCEstablishmentCause (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 5, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RRCEstablishmentCause (%d): %w", ieId, err)
			}
			result := RRCEstablishmentCause(v)
			return &result, nil
		case 96: // id-S-TMSI -> STMSI
			var v STMSI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE STMSI (%d): %w", ieId, err)
			}
			return &v, nil
		case 127: // id-CSG-Id -> CSGId (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 27, 27, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGId (%d): %w", ieId, err)
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
		case 160: // id-RelayNode-Indicator -> RelayNodeIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RelayNodeIndicator (%d): %w", ieId, err)
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
		case 186: // id-LHN-ID -> LHNID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 32, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LHNID (%d): %w", ieId, err)
			}
			result := LHNID(v)
			return &result, nil
		case 223: // id-MME-Group-ID -> MMEGroupID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 2, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEGroupID (%d): %w", ieId, err)
			}
			result := MMEGroupID(v)
			return &result, nil
		case 230: // id-UE-Usage-Type -> UEUsageType (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEUsageType (%d): %w", ieId, err)
			}
			result := UEUsageType(v)
			return &result, nil
		case 242: // id-CE-mode-B-SupportIndicator -> CEModeBSupportIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CEModeBSupportIndicator (%d): %w", ieId, err)
			}
			result := CEModeBSupportIndicator(v)
			return &result, nil
		case 246: // id-DCN-ID -> DCNID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(65535), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE DCNID (%d): %w", ieId, err)
			}
			result := DCNID(v)
			return &result, nil
		case 250: // id-Coverage-Level -> CoverageLevel (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CoverageLevel (%d): %w", ieId, err)
			}
			result := CoverageLevel(v)
			return &result, nil
		case 263: // id-UE-Application-Layer-Measurement-Capability -> UEApplicationLayerMeasurementCapability (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEApplicationLayerMeasurementCapability (%d): %w", ieId, err)
			}
			result := UEApplicationLayerMeasurementCapability{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 281: // id-EDT-Session -> EDTSession (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EDTSession (%d): %w", ieId, err)
			}
			result := EDTSession(v)
			return &result, nil
		case 302: // id-IAB-Node-Indication -> IABNodeIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IABNodeIndication (%d): %w", ieId, err)
			}
			result := IABNodeIndication(v)
			return &result, nil
		case 339: // id-LTE-NTN-TAI-Information -> LTENTNTAIInformation
			var v LTENTNTAIInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LTENTNTAIInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 353: // id-CoarseUELocationRequested -> CoarseUELocationRequested (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CoarseUELocationRequested (%d): %w", ieId, err)
			}
			result := CoarseUELocationRequested(v)
			return &result, nil
		}
	case "UplinkNASTransport-IEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 26: // id-NAS-PDU -> NASPDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NASPDU (%d): %w", ieId, err)
			}
			result := NASPDU(v)
			return &result, nil
		case 100: // id-EUTRAN-CGI -> EUTRANCGI
			var v EUTRANCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EUTRANCGI (%d): %w", ieId, err)
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
		case 186: // id-LHN-ID -> LHNID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 32, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LHNID (%d): %w", ieId, err)
			}
			result := LHNID(v)
			return &result, nil
		case 288: // id-PSCellInformation -> PSCellInformation
			var v PSCellInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE PSCellInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 339: // id-LTE-NTN-TAI-Information -> LTENTNTAIInformation
			var v LTENTNTAIInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LTENTNTAIInformation (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "NASNonDeliveryIndication-IEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 26: // id-NAS-PDU -> NASPDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NASPDU (%d): %w", ieId, err)
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
	case "RerouteNASRequest-IEs":
		switch ieId {
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 225: // id-S1-Message -> S1Message (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE S1Message (%d): %w", ieId, err)
			}
			result := S1Message(v)
			return &result, nil
		case 223: // id-MME-Group-ID -> MMEGroupID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 2, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEGroupID (%d): %w", ieId, err)
			}
			result := MMEGroupID(v)
			return &result, nil
		case 224: // id-Additional-GUTI -> AdditionalGUTI
			var v AdditionalGUTI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE AdditionalGUTI (%d): %w", ieId, err)
			}
			return &v, nil
		case 230: // id-UE-Usage-Type -> UEUsageType (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEUsageType (%d): %w", ieId, err)
			}
			result := UEUsageType(v)
			return &result, nil
		}
	case "NASDeliveryIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		}
	case "ResetIEs":
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
	case "UE-associatedLogicalS1-ConnectionItemRes":
		switch ieId {
		case 91: // id-UE-associatedLogicalS1-ConnectionItem -> UEAssociatedLogicalS1ConnectionItem
			var v UEAssociatedLogicalS1ConnectionItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEAssociatedLogicalS1ConnectionItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ResetAcknowledgeIEs":
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
	case "UE-associatedLogicalS1-ConnectionItemResAck":
		switch ieId {
		case 91: // id-UE-associatedLogicalS1-ConnectionItem -> UEAssociatedLogicalS1ConnectionItem
			var v UEAssociatedLogicalS1ConnectionItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEAssociatedLogicalS1ConnectionItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ErrorIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
		case 96: // id-S-TMSI -> STMSI
			var v STMSI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE STMSI (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "S1SetupRequestIEs":
		switch ieId {
		case 59: // id-Global-ENB-ID -> GlobalENBID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENBID (%d): %w", ieId, err)
			}
			return &v, nil
		case 60: // id-eNBname -> ENBname (PrintableString)
			v, err := per.DecodeKnownMultiplierStringAlignedExt(bb, 7, 1, 150, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBname (%d): %w", ieId, err)
			}
			result := ENBname(v)
			return &result, nil
		case 64: // id-SupportedTAs -> SupportedTAs (SEQUENCE_OF)
			v, err := UnmarshalAPERSupportedTAsFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SupportedTAs (%d): %w", ieId, err)
			}
			return &v, nil
		case 137: // id-DefaultPagingDRX -> PagingDRX (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PagingDRX (%d): %w", ieId, err)
			}
			result := PagingDRX(v)
			return &result, nil
		case 128: // id-CSG-IdList -> CSGIdList (SEQUENCE_OF)
			v, err := UnmarshalAPERCSGIdListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGIdList (%d): %w", ieId, err)
			}
			return &v, nil
		case 228: // id-UE-RetentionInformation -> UERetentionInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERetentionInformation (%d): %w", ieId, err)
			}
			result := UERetentionInformation(v)
			return &result, nil
		case 234: // id-NB-IoT-DefaultPagingDRX -> NBIoTDefaultPagingDRX (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NBIoTDefaultPagingDRX (%d): %w", ieId, err)
			}
			result := NBIoTDefaultPagingDRX(v)
			return &result, nil
		case 291: // id-ConnectedengNBList -> ConnectedengNBList (SEQUENCE_OF)
			v, err := UnmarshalAPERConnectedengNBListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ConnectedengNBList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "S1SetupResponseIEs":
		switch ieId {
		case 61: // id-MMEname -> MMEname (PrintableString)
			v, err := per.DecodeKnownMultiplierStringAlignedExt(bb, 7, 1, 150, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEname (%d): %w", ieId, err)
			}
			result := MMEname(v)
			return &result, nil
		case 105: // id-ServedGUMMEIs -> ServedGUMMEIs (SEQUENCE_OF)
			v, err := UnmarshalAPERServedGUMMEIsFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedGUMMEIs (%d): %w", ieId, err)
			}
			return &v, nil
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
		case 228: // id-UE-RetentionInformation -> UERetentionInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERetentionInformation (%d): %w", ieId, err)
			}
			result := UERetentionInformation(v)
			return &result, nil
		case 247: // id-ServedDCNs -> ServedDCNs (SEQUENCE_OF)
			v, err := UnmarshalAPERServedDCNsFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedDCNs (%d): %w", ieId, err)
			}
			return &v, nil
		case 303: // id-IAB-Supported -> IABSupported (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IABSupported (%d): %w", ieId, err)
			}
			result := IABSupported(v)
			return &result, nil
		}
	case "S1SetupFailureIEs":
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
	case "ENBConfigurationUpdateIEs":
		switch ieId {
		case 60: // id-eNBname -> ENBname (PrintableString)
			v, err := per.DecodeKnownMultiplierStringAlignedExt(bb, 7, 1, 150, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBname (%d): %w", ieId, err)
			}
			result := ENBname(v)
			return &result, nil
		case 64: // id-SupportedTAs -> SupportedTAs (SEQUENCE_OF)
			v, err := UnmarshalAPERSupportedTAsFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SupportedTAs (%d): %w", ieId, err)
			}
			return &v, nil
		case 128: // id-CSG-IdList -> CSGIdList (SEQUENCE_OF)
			v, err := UnmarshalAPERCSGIdListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGIdList (%d): %w", ieId, err)
			}
			return &v, nil
		case 137: // id-DefaultPagingDRX -> PagingDRX (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PagingDRX (%d): %w", ieId, err)
			}
			result := PagingDRX(v)
			return &result, nil
		case 234: // id-NB-IoT-DefaultPagingDRX -> NBIoTDefaultPagingDRX (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NBIoTDefaultPagingDRX (%d): %w", ieId, err)
			}
			result := NBIoTDefaultPagingDRX(v)
			return &result, nil
		case 292: // id-ConnectedengNBToAddList -> ConnectedengNBList (SEQUENCE_OF)
			v, err := UnmarshalAPERConnectedengNBListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ConnectedengNBList (%d): %w", ieId, err)
			}
			return &v, nil
		case 293: // id-ConnectedengNBToRemoveList -> ConnectedengNBList (SEQUENCE_OF)
			v, err := UnmarshalAPERConnectedengNBListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ConnectedengNBList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENBConfigurationUpdateAcknowledgeIEs":
		switch ieId {
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENBConfigurationUpdateFailureIEs":
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
	case "MMEConfigurationUpdateIEs":
		switch ieId {
		case 61: // id-MMEname -> MMEname (PrintableString)
			v, err := per.DecodeKnownMultiplierStringAlignedExt(bb, 7, 1, 150, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEname (%d): %w", ieId, err)
			}
			result := MMEname(v)
			return &result, nil
		case 105: // id-ServedGUMMEIs -> ServedGUMMEIs (SEQUENCE_OF)
			v, err := UnmarshalAPERServedGUMMEIsFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedGUMMEIs (%d): %w", ieId, err)
			}
			return &v, nil
		case 87: // id-RelativeMMECapacity -> RelativeMMECapacity (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RelativeMMECapacity (%d): %w", ieId, err)
			}
			result := RelativeMMECapacity(v)
			return &result, nil
		case 247: // id-ServedDCNs -> ServedDCNs (SEQUENCE_OF)
			v, err := UnmarshalAPERServedDCNsFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedDCNs (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MMEConfigurationUpdateAcknowledgeIEs":
		switch ieId {
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MMEConfigurationUpdateFailureIEs":
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
	case "DownlinkS1cdma2000tunnellingIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "UplinkS1cdma2000tunnellingIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "UECapabilityInfoIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
		case 263: // id-UE-Application-Layer-Measurement-Capability -> UEApplicationLayerMeasurementCapability (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEApplicationLayerMeasurementCapability (%d): %w", ieId, err)
			}
			result := UEApplicationLayerMeasurementCapability{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 272: // id-LTE-M-Indication -> LTEMIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LTEMIndication (%d): %w", ieId, err)
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
	case "ENBStatusTransferIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 90: // id-eNB-StatusTransfer-TransparentContainer -> ENBStatusTransferTransparentContainer
			var v ENBStatusTransferTransparentContainer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ENBStatusTransferTransparentContainer (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MMEStatusTransferIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 90: // id-eNB-StatusTransfer-TransparentContainer -> ENBStatusTransferTransparentContainer
			var v ENBStatusTransferTransparentContainer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ENBStatusTransferTransparentContainer (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "TraceStartIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "TraceFailureIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 86: // id-E-UTRAN-Trace-ID -> EUTRANTraceID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EUTRANTraceID (%d): %w", ieId, err)
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
	case "DeactivateTraceIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 86: // id-E-UTRAN-Trace-ID -> EUTRANTraceID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EUTRANTraceID (%d): %w", ieId, err)
			}
			result := EUTRANTraceID(v)
			return &result, nil
		}
	case "CellTrafficTraceIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 86: // id-E-UTRAN-Trace-ID -> EUTRANTraceID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EUTRANTraceID (%d): %w", ieId, err)
			}
			result := EUTRANTraceID(v)
			return &result, nil
		case 100: // id-EUTRAN-CGI -> EUTRANCGI
			var v EUTRANCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EUTRANCGI (%d): %w", ieId, err)
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
	case "LocationReportingControlIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "LocationReportingFailureIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "LocationReportIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 100: // id-EUTRAN-CGI -> EUTRANCGI
			var v EUTRANCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EUTRANCGI (%d): %w", ieId, err)
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
		case 339: // id-LTE-NTN-TAI-Information -> LTENTNTAIInformation
			var v LTENTNTAIInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LTENTNTAIInformation (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "OverloadStartIEs":
		switch ieId {
		case 101: // id-OverloadResponse -> OverloadResponse
			var v OverloadResponse
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE OverloadResponse (%d): %w", ieId, err)
			}
			return &v, nil
		case 154: // id-GUMMEIList -> GUMMEIList (SEQUENCE_OF)
			v, err := UnmarshalAPERGUMMEIListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GUMMEIList (%d): %w", ieId, err)
			}
			return &v, nil
		case 161: // id-TrafficLoadReductionIndication -> TrafficLoadReductionIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(99), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TrafficLoadReductionIndication (%d): %w", ieId, err)
			}
			result := TrafficLoadReductionIndication(v)
			return &result, nil
		}
	case "OverloadStopIEs":
		switch ieId {
		case 154: // id-GUMMEIList -> GUMMEIList (SEQUENCE_OF)
			v, err := UnmarshalAPERGUMMEIListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GUMMEIList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "WriteReplaceWarningRequestIEs":
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
	case "WriteReplaceWarningResponseIEs":
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
	case "ENBDirectInformationTransferIEs":
		switch ieId {
		case 121: // id-Inter-SystemInformationTransferTypeEDT -> InterSystemInformationTransferType
			var v InterSystemInformationTransferType
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE InterSystemInformationTransferType (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MMEDirectInformationTransferIEs":
		switch ieId {
		case 122: // id-Inter-SystemInformationTransferTypeMDT -> InterSystemInformationTransferType
			var v InterSystemInformationTransferType
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE InterSystemInformationTransferType (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENBConfigurationTransferIEs":
		switch ieId {
		case 129: // id-SONConfigurationTransferECT -> SONConfigurationTransfer
			var v SONConfigurationTransfer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SONConfigurationTransfer (%d): %w", ieId, err)
			}
			return &v, nil
		case 294: // id-EN-DCSONConfigurationTransfer-ECT -> ENDCSONConfigurationTransfer
			var v ENDCSONConfigurationTransfer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ENDCSONConfigurationTransfer (%d): %w", ieId, err)
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
	case "MMEConfigurationTransferIEs":
		switch ieId {
		case 130: // id-SONConfigurationTransferMCT -> SONConfigurationTransfer
			var v SONConfigurationTransfer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SONConfigurationTransfer (%d): %w", ieId, err)
			}
			return &v, nil
		case 295: // id-EN-DCSONConfigurationTransfer-MCT -> ENDCSONConfigurationTransfer
			var v ENDCSONConfigurationTransfer
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ENDCSONConfigurationTransfer (%d): %w", ieId, err)
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
	case "KillRequestIEs":
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
	case "KillResponseIEs":
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
	case "PWSRestartIndicationIEs":
		switch ieId {
		case 182: // id-ECGIListForRestart -> ECGIListForRestart (SEQUENCE_OF)
			v, err := UnmarshalAPERECGIListForRestartFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ECGIListForRestart (%d): %w", ieId, err)
			}
			return &v, nil
		case 59: // id-Global-ENB-ID -> GlobalENBID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENBID (%d): %w", ieId, err)
			}
			return &v, nil
		case 188: // id-TAIListForRestart -> TAIListForRestart (SEQUENCE_OF)
			v, err := UnmarshalAPERTAIListForRestartFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TAIListForRestart (%d): %w", ieId, err)
			}
			return &v, nil
		case 190: // id-EmergencyAreaIDListForRestart -> EmergencyAreaIDListForRestart (SEQUENCE_OF)
			v, err := UnmarshalAPEREmergencyAreaIDListForRestartFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EmergencyAreaIDListForRestart (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "PWSFailureIndicationIEs":
		switch ieId {
		case 222: // id-PWSfailedECGIList -> PWSfailedECGIList (SEQUENCE_OF)
			v, err := UnmarshalAPERPWSfailedECGIListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PWSfailedECGIList (%d): %w", ieId, err)
			}
			return &v, nil
		case 59: // id-Global-ENB-ID -> GlobalENBID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENBID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "DownlinkUEAssociatedLPPaTransport-IEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 148: // id-Routing-ID -> RoutingID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RoutingID (%d): %w", ieId, err)
			}
			result := RoutingID(v)
			return &result, nil
		case 147: // id-LPPa-PDU -> LPPaPDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LPPaPDU (%d): %w", ieId, err)
			}
			result := LPPaPDU(v)
			return &result, nil
		}
	case "UplinkUEAssociatedLPPaTransport-IEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 148: // id-Routing-ID -> RoutingID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RoutingID (%d): %w", ieId, err)
			}
			result := RoutingID(v)
			return &result, nil
		case 147: // id-LPPa-PDU -> LPPaPDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LPPaPDU (%d): %w", ieId, err)
			}
			result := LPPaPDU(v)
			return &result, nil
		}
	case "DownlinkNonUEAssociatedLPPaTransport-IEs":
		switch ieId {
		case 148: // id-Routing-ID -> RoutingID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RoutingID (%d): %w", ieId, err)
			}
			result := RoutingID(v)
			return &result, nil
		case 147: // id-LPPa-PDU -> LPPaPDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LPPaPDU (%d): %w", ieId, err)
			}
			result := LPPaPDU(v)
			return &result, nil
		}
	case "UplinkNonUEAssociatedLPPaTransport-IEs":
		switch ieId {
		case 148: // id-Routing-ID -> RoutingID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RoutingID (%d): %w", ieId, err)
			}
			result := RoutingID(v)
			return &result, nil
		case 147: // id-LPPa-PDU -> LPPaPDU (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LPPaPDU (%d): %w", ieId, err)
			}
			result := LPPaPDU(v)
			return &result, nil
		}
	case "E-RABModificationIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "E-RABToBeModifiedItemBearerModIndIEs":
		switch ieId {
		case 200: // id-E-RABToBeModifiedItemBearerModInd -> ERABToBeModifiedItemBearerModInd
			var v ERABToBeModifiedItemBearerModInd
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABToBeModifiedItemBearerModInd (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABNotToBeModifiedItemBearerModIndIEs":
		switch ieId {
		case 202: // id-E-RABNotToBeModifiedItemBearerModInd -> ERABNotToBeModifiedItemBearerModInd
			var v ERABNotToBeModifiedItemBearerModInd
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABNotToBeModifiedItemBearerModInd (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABModificationConfirmIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 203: // id-E-RABModifyListBearerModConf -> ERABModifyListBearerModConf (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABModifyListBearerModConf (%d): %w", ieId, err)
			}
			return &v, nil
		case 205: // id-E-RABFailedToModifyListBearerModConf -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 210: // id-E-RABToBeReleasedListBearerModConf -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
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
	case "E-RABModifyItemBearerModConfIEs":
		switch ieId {
		case 204: // id-E-RABModifyItemBearerModConf -> ERABModifyItemBearerModConf
			var v ERABModifyItemBearerModConf
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABModifyItemBearerModConf (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextModificationIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "UEContextModificationConfirmIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "UEContextSuspendRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "UEContextSuspendResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "UEContextResumeRequestIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 235: // id-E-RABFailedToResumeListResumeReq -> ERABFailedToResumeListResumeReq (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABFailedToResumeListResumeReq (%d): %w", ieId, err)
			}
			return &v, nil
		case 245: // id-RRC-Resume-Cause -> RRCEstablishmentCause (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 5, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RRCEstablishmentCause (%d): %w", ieId, err)
			}
			result := RRCEstablishmentCause(v)
			return &result, nil
		}
	case "E-RABFailedToResumeItemResumeReqIEs":
		switch ieId {
		case 236: // id-E-RABFailedToResumeItemResumeReq -> ERABFailedToResumeItemResumeReq
			var v ERABFailedToResumeItemResumeReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABFailedToResumeItemResumeReq (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextResumeResponseIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "E-RABFailedToResumeItemResumeResIEs":
		switch ieId {
		case 238: // id-E-RABFailedToResumeItemResumeRes -> ERABFailedToResumeItemResumeRes
			var v ERABFailedToResumeItemResumeRes
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABFailedToResumeItemResumeRes (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextResumeFailureIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "ConnectionEstablishmentIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
		case 253: // id-DL-CP-SecurityInformation -> DLCPSecurityInformation
			var v DLCPSecurityInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE DLCPSecurityInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 271: // id-CE-ModeBRestricted -> CEModeBRestricted (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CEModeBRestricted (%d): %w", ieId, err)
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
		case 278: // id-Subscription-Based-UE-DifferentiationInfo -> SubscriptionBasedUEDifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SubscriptionBasedUEDifferentiationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 252: // id-UE-Level-QoS-Parameters -> ERABLevelQoSParameters
			var v ERABLevelQoSParameters
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABLevelQoSParameters (%d): %w", ieId, err)
			}
			return &v, nil
		case 314: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityID (%d): %w", ieId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		case 192: // id-Masked-IMEISV -> MaskedIMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MaskedIMEISV (%d): %w", ieId, err)
			}
			result := MaskedIMEISV{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 354: // id-CoarseUELocation -> CoarseUELocation (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CoarseUELocation (%d): %w", ieId, err)
			}
			result := CoarseUELocation(v)
			return &result, nil
		}
	case "RetrieveUEInformationIEs":
		switch ieId {
		case 96: // id-S-TMSI -> STMSI
			var v STMSI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE STMSI (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEInformationTransferIEs":
		switch ieId {
		case 96: // id-S-TMSI -> STMSI
			var v STMSI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE STMSI (%d): %w", ieId, err)
			}
			return &v, nil
		case 252: // id-UE-Level-QoS-Parameters -> ERABLevelQoSParameters
			var v ERABLevelQoSParameters
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABLevelQoSParameters (%d): %w", ieId, err)
			}
			return &v, nil
		case 74: // id-UERadioCapability -> UERadioCapability (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapability (%d): %w", ieId, err)
			}
			result := UERadioCapability(v)
			return &result, nil
		case 278: // id-Subscription-Based-UE-DifferentiationInfo -> SubscriptionBasedUEDifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SubscriptionBasedUEDifferentiationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 283: // id-PendingDataIndication -> PendingDataIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PendingDataIndication (%d): %w", ieId, err)
			}
			result := PendingDataIndication(v)
			return &result, nil
		case 192: // id-Masked-IMEISV -> MaskedIMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MaskedIMEISV (%d): %w", ieId, err)
			}
			result := MaskedIMEISV{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ENBCPRelocationIndicationIEs":
		switch ieId {
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 96: // id-S-TMSI -> STMSI
			var v STMSI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE STMSI (%d): %w", ieId, err)
			}
			return &v, nil
		case 100: // id-EUTRAN-CGI -> EUTRANCGI
			var v EUTRANCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE EUTRANCGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 67: // id-TAI -> TAI
			var v TAI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TAI (%d): %w", ieId, err)
			}
			return &v, nil
		case 254: // id-UL-CP-SecurityInformation -> ULCPSecurityInformation
			var v ULCPSecurityInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ULCPSecurityInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 339: // id-LTE-NTN-TAI-Information -> LTENTNTAIInformation
			var v LTENTNTAIInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LTENTNTAIInformation (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MMECPRelocationIndicationIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		}
	case "SecondaryRATDataUsageReportIEs":
		switch ieId {
		case 0: // id-MME-UE-S1AP-ID -> MMEUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEUES1APID (%d): %w", ieId, err)
			}
			result := MMEUES1APID(v)
			return &result, nil
		case 8: // id-eNB-UE-S1AP-ID -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ENBUES1APID (%d): %w", ieId, err)
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
	case "UERadioCapabilityIDMappingRequestIEs":
		switch ieId {
		case 314: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityID (%d): %w", ieId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		}
	case "UERadioCapabilityIDMappingResponseIEs":
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
	case "S1RemovalRequestIEs":
		switch ieId {
		case 59: // id-Global-ENB-ID -> GlobalENBID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENBID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "S1RemovalResponseIEs":
		switch ieId {
		case 61: // id-MMEname -> MMEname (PrintableString)
			v, err := per.DecodeKnownMultiplierStringAlignedExt(bb, 7, 1, 150, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MMEname (%d): %w", ieId, err)
			}
			result := MMEname(v)
			return &result, nil
		case 58: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "S1RemovalFailureIEs":
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
	result := make([]ProtocolIEField, 0)
	for i := int64(0); i < n; i++ {
		var item ProtocolIEField
		if err := item.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding item %d: %w", i, err)
		}
		result = append(result, item)
	}
	return result, nil
}

// DecodeExtensionFieldValue decodes a known extension open value using its object-set context and ID.
// Returns the decoded typed value, or nil if the combination is unknown.
func DecodeExtensionFieldValue(objectSet string, extensionId int64, data []byte) (interface{}, error) {
	bb := per.NewBitBufferFromBytes(data)
	switch objectSet {
	case "Bearers-SubjectToStatusTransfer-ItemExtIEs":
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
		case 217: // id-ULCOUNTValuePDCP-SNlength18 -> COUNTvaluePDCPSNlength18
			var v COUNTvaluePDCPSNlength18
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension COUNTvaluePDCPSNlength18 (%d): %w", extensionId, err)
			}
			return &v, nil
		case 218: // id-DLCOUNTValuePDCP-SNlength18 -> COUNTvaluePDCPSNlength18
			var v COUNTvaluePDCPSNlength18
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension COUNTvaluePDCPSNlength18 (%d): %w", extensionId, err)
			}
			return &v, nil
		case 219: // id-ReceiveStatusOfULPDCPSDUsPDCP-SNlength18 -> ReceiveStatusOfULPDCPSDUsPDCPSNlength18 (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 1, 131072, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ReceiveStatusOfULPDCPSDUsPDCPSNlength18 (%d): %w", extensionId, err)
			}
			result := ReceiveStatusOfULPDCPSDUsPDCPSNlength18{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs":
		switch extensionId {
		case 352: // id-Bearers-SubjectToDLDiscardingList -> BearersSubjectToDLDiscardingList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeExtensionProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding extension BearersSubjectToDLDiscardingList (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "E-RABInformationListItem-ExtIEs":
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
	case "E-RABQoSParameters-ExtIEs":
		switch extensionId {
		case 273: // id-DownlinkPacketLossRate -> PacketLossRate (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(1000), false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PacketLossRate (%d): %w", extensionId, err)
			}
			result := PacketLossRate(v)
			return &result, nil
		case 274: // id-UplinkPacketLossRate -> PacketLossRate (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(1000), false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PacketLossRate (%d): %w", extensionId, err)
			}
			result := PacketLossRate(v)
			return &result, nil
		}
	case "GBR-QosInformation-ExtIEs":
		switch extensionId {
		case 255: // id-extended-e-RAB-MaximumBitrateDL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("10000000001"), runtime.MustParseBigIntDecimal("4000000000000"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			return v, nil
		case 256: // id-extended-e-RAB-MaximumBitrateUL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("10000000001"), runtime.MustParseBigIntDecimal("4000000000000"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			return v, nil
		case 257: // id-extended-e-RAB-GuaranteedBitrateDL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("10000000001"), runtime.MustParseBigIntDecimal("4000000000000"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			return v, nil
		case 258: // id-extended-e-RAB-GuaranteedBitrateUL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("10000000001"), runtime.MustParseBigIntDecimal("4000000000000"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			return v, nil
		}
	case "HandoverRestrictionList-ExtIEs":
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
		case 282: // id-CNTypeRestrictions -> CNTypeRestrictions (SEQUENCE_OF)
			v, err := UnmarshalAPERCNTypeRestrictionsFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CNTypeRestrictions (%d): %w", extensionId, err)
			}
			return &v, nil
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
		case 336: // id-RAT-Restrictions -> RATRestrictions (SEQUENCE_OF)
			v, err := UnmarshalAPERRATRestrictionsFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension RATRestrictions (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ImmediateMDT-ExtIEs":
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
		case 174: // id-MDT-Location-Info -> MDTLocationInfo (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MDTLocationInfo (%d): %w", extensionId, err)
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
	case "LastVisitedEUTRANCellInformation-ExtIEs":
		switch extensionId {
		case 167: // id-Time-UE-StayedInCell-EnhancedGranularity -> TimeUEStayedInCellEnhancedGranularity (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(40950), false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TimeUEStayedInCellEnhancedGranularity (%d): %w", extensionId, err)
			}
			result := TimeUEStayedInCellEnhancedGranularity(v)
			return &result, nil
		case 168: // id-HO-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension Cause (%d): %w", extensionId, err)
			}
			return &v, nil
		case 329: // id-lastVisitedPSCellList -> LastVisitedPSCellList (SEQUENCE_OF)
			v, err := UnmarshalAPERLastVisitedPSCellListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension LastVisitedPSCellList (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "LoggedMDT-ExtIEs":
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
	case "M4Configuration-ExtIEs":
		switch extensionId {
		case 346: // id-M4ReportAmount -> M4ReportAmountMDT (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension M4ReportAmountMDT (%d): %w", extensionId, err)
			}
			result := M4ReportAmountMDT(v)
			return &result, nil
		}
	case "M5Configuration-ExtIEs":
		switch extensionId {
		case 347: // id-M5ReportAmount -> M5ReportAmountMDT (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension M5ReportAmountMDT (%d): %w", extensionId, err)
			}
			result := M5ReportAmountMDT(v)
			return &result, nil
		}
	case "M6Configuration-ExtIEs":
		switch extensionId {
		case 348: // id-M6ReportAmount -> M6ReportAmountMDT (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension M6ReportAmountMDT (%d): %w", extensionId, err)
			}
			result := M6ReportAmountMDT(v)
			return &result, nil
		}
	case "M7Configuration-ExtIEs":
		switch extensionId {
		case 349: // id-M7ReportAmount -> M7ReportAmountMDT (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension M7ReportAmountMDT (%d): %w", extensionId, err)
			}
			result := M7ReportAmountMDT(v)
			return &result, nil
		}
	case "MDT-Configuration-ExtIEs":
		switch extensionId {
		case 178: // id-SignallingBasedMDTPLMNList -> MDTPLMNList (SEQUENCE_OF)
			v, err := UnmarshalAPERMDTPLMNListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MDTPLMNList (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ProSeAuthorized-ExtIEs":
		switch extensionId {
		case 216: // id-ProSeUEtoNetworkRelaying -> ProSeUEtoNetworkRelaying (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ProSeUEtoNetworkRelaying (%d): %w", extensionId, err)
			}
			result := ProSeUEtoNetworkRelaying(v)
			return &result, nil
		}
	case "RequestType-ExtIEs":
		switch extensionId {
		case 298: // id-RequestTypeAdditionalInfo -> RequestTypeAdditionalInfo (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension RequestTypeAdditionalInfo (%d): %w", extensionId, err)
			}
			result := RequestTypeAdditionalInfo(v)
			return &result, nil
		}
	case "RLFReportInformation-ExtIEs":
		switch extensionId {
		case 313: // id-NB-IoT-RLF-Report-Container -> NBIoTRLFReportContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NBIoTRLFReportContainer (%d): %w", extensionId, err)
			}
			result := NBIoTRLFReportContainer(v)
			return &result, nil
		}
	case "SONInformationReply-ExtIEs":
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
	case "SONConfigurationTransfer-ExtIEs":
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
		case 356: // id-RequestedTNLInfo -> RequestedTNLInfo
			var v RequestedTNLInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension RequestedTNLInfo (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs":
		switch extensionId {
		case 175: // id-MobilityInformation -> MobilityInformation (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MobilityInformation (%d): %w", extensionId, err)
			}
			result := MobilityInformation{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 194: // id-uE-HistoryInformationFromTheUE -> UEHistoryInformationFromTheUE (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension UEHistoryInformationFromTheUE (%d): %w", extensionId, err)
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
		case 337: // id-UEContextReferenceatSourceeNB -> ENBUES1APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(16777215), false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ENBUES1APID (%d): %w", extensionId, err)
			}
			result := ENBUES1APID(v)
			return &result, nil
		case 343: // id-SourceSNID -> GlobalRANNODEID
			var v GlobalRANNODEID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension GlobalRANNODEID (%d): %w", extensionId, err)
			}
			return &v, nil
		case 79: // id-Direct-Forwarding-Path-Availability -> DirectForwardingPathAvailability (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension DirectForwardingPathAvailability (%d): %w", extensionId, err)
			}
			result := DirectForwardingPathAvailability(v)
			return &result, nil
		case 350: // id-TimeBasedHandoverInformation -> TimeBasedHandoverInformation
			var v TimeBasedHandoverInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension TimeBasedHandoverInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ServedGUMMEIsItem-ExtIEs":
		switch extensionId {
		case 170: // id-GUMMEIType -> GUMMEIType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension GUMMEIType (%d): %w", extensionId, err)
			}
			result := GUMMEIType(v)
			return &result, nil
		}
	case "SupportedTAs-Item-ExtIEs":
		switch extensionId {
		case 232: // id-RAT-Type -> RATType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension RATType (%d): %w", extensionId, err)
			}
			result := RATType(v)
			return &result, nil
		}
	case "TimeSynchronisationInfo-ExtIEs":
		switch extensionId {
		case 207: // id-Muting-Availability-Indication -> MutingAvailabilityIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MutingAvailabilityIndication (%d): %w", extensionId, err)
			}
			result := MutingAvailabilityIndication(v)
			return &result, nil
		}
	case "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs":
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
		case 335: // id-E-RABSecurityResultList -> ERABSecurityResultList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeExtensionProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ERABSecurityResultList (%d): %w", extensionId, err)
			}
			return &v, nil
		case 79: // id-Direct-Forwarding-Path-Availability -> DirectForwardingPathAvailability (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension DirectForwardingPathAvailability (%d): %w", extensionId, err)
			}
			result := DirectForwardingPathAvailability(v)
			return &result, nil
		}
	case "TraceActivation-ExtIEs":
		switch extensionId {
		case 162: // id-MDTConfiguration -> MDTConfiguration
			var v MDTConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension MDTConfiguration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 262: // id-UEAppLayerMeasConfig -> UEAppLayerMeasConfig
			var v UEAppLayerMeasConfig
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension UEAppLayerMeasConfig (%d): %w", extensionId, err)
			}
			return &v, nil
		case 316: // id-MDTConfigurationNR -> MDTConfigurationNR (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MDTConfigurationNR (%d): %w", extensionId, err)
			}
			result := MDTConfigurationNR(v)
			return &result, nil
		case 325: // id-TraceCollectionEntityURI -> URIAddress (VisibleString)
			v, err := per.DecodeKnownMultiplierStringAligned(bb, 7, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension URIAddress (%d): %w", extensionId, err)
			}
			result := URIAddress(v)
			return &result, nil
		}
	case "UEAggregate-MaximumBitrates-ExtIEs":
		switch extensionId {
		case 259: // id-extended-uEaggregateMaximumBitRateDL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("10000000001"), runtime.MustParseBigIntDecimal("4000000000000"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			return v, nil
		case 260: // id-extended-uEaggregateMaximumBitRateUL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("10000000001"), runtime.MustParseBigIntDecimal("4000000000000"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			return v, nil
		}
	case "UEAppLayerMeasConfig-ExtIEs":
		switch extensionId {
		case 276: // id-serviceType -> ServiceType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ServiceType (%d): %w", extensionId, err)
			}
			result := ServiceType(v)
			return &result, nil
		}
	case "UserLocationInformation-ExtIEs":
		switch extensionId {
		case 288: // id-PSCellInformation -> PSCellInformation
			var v PSCellInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension PSCellInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		case 339: // id-LTE-NTN-TAI-Information -> LTENTNTAIInformation
			var v LTENTNTAIInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension LTENTNTAIInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "X2TNLConfigurationInfo-ExtIEs":
		switch extensionId {
		case 153: // id-eNBX2ExtendedTransportLayerAddresses -> ENBX2ExtTLAs (SEQUENCE_OF)
			v, err := UnmarshalAPERENBX2ExtTLAsFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ENBX2ExtTLAs (%d): %w", extensionId, err)
			}
			return &v, nil
		case 193: // id-eNBIndirectX2TransportLayerAddresses -> ENBIndirectX2TransportLayerAddresses (SEQUENCE_OF)
			v, err := UnmarshalAPERENBIndirectX2TransportLayerAddressesFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ENBIndirectX2TransportLayerAddresses (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "E-RABToBeSetupItemHOReq-ExtIEs":
		switch extensionId {
		case 143: // id-Data-Forwarding-Not-Possible -> DataForwardingNotPossible (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension DataForwardingNotPossible (%d): %w", extensionId, err)
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
		case 305: // id-Ethernet-Type -> EthernetType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EthernetType (%d): %w", extensionId, err)
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
	case "E-RABToBeSwitchedDLItem-ExtIEs":
		switch extensionId {
		case 332: // id-SecurityIndication -> SecurityIndication
			var v SecurityIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SecurityIndication (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "E-RABToBeSetupItemBearerSUReqExtIEs":
		switch extensionId {
		case 156: // id-Correlation-ID -> CorrelationID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CorrelationID (%d): %w", extensionId, err)
			}
			result := CorrelationID(v)
			return &result, nil
		case 183: // id-SIPTO-Correlation-ID -> CorrelationID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CorrelationID (%d): %w", extensionId, err)
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
		case 305: // id-Ethernet-Type -> EthernetType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EthernetType (%d): %w", extensionId, err)
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
	case "E-RABToBeModifyItemBearerModReqExtIEs":
		switch extensionId {
		case 185: // id-TransportInformation -> TransportInformation
			var v TransportInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension TransportInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "E-RABToBeSetupItemCtxtSUReqExtIEs":
		switch extensionId {
		case 156: // id-Correlation-ID -> CorrelationID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CorrelationID (%d): %w", extensionId, err)
			}
			result := CorrelationID(v)
			return &result, nil
		case 183: // id-SIPTO-Correlation-ID -> CorrelationID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CorrelationID (%d): %w", extensionId, err)
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
		case 305: // id-Ethernet-Type -> EthernetType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EthernetType (%d): %w", extensionId, err)
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
	"EventTrigger.ChoiceExtensions":                                                      "EventTrigger-ExtIEs",
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
	"MeasurementThresholdL1LoggedMDT.ChoiceExtensions":                                   "MeasurementThresholdL1LoggedMDT-ExtIEs",
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
	"S1RemovalFailure.ProtocolIEs":                                                       "S1RemovalFailureIEs",
	"S1RemovalRequest.ProtocolIEs":                                                       "S1RemovalRequestIEs",
	"S1RemovalResponse.ProtocolIEs":                                                      "S1RemovalResponseIEs",
	"S1SetupFailure.ProtocolIEs":                                                         "S1SetupFailureIEs",
	"S1SetupRequest.ProtocolIEs":                                                         "S1SetupRequestIEs",
	"S1SetupResponse.ProtocolIEs":                                                        "S1SetupResponseIEs",
	"SecondaryRATDataUsageReport.ProtocolIEs":                                            "SecondaryRATDataUsageReportIEs",
	"SecondaryRATDataUsageReportItem.ERABUsageReportList":                                "E-RABUsageReportItemIEs",
	"SensorNameConfig.ChoiceExtensions":                                                  "SensorNameConfig-ExtIEs",
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
	"BearersSubjectToDLDiscardingList":          "Bearers-SubjectToDLDiscarding-ItemIEs",
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
	"SourceNodeIDExtension":                     "SourceNodeID-ExtensionIE",
	"TAIList":                                   "TAIItemIEs",
	"UEAssociatedLogicalS1ConnectionListRes":    "UE-associatedLogicalS1-ConnectionItemRes",
	"UEAssociatedLogicalS1ConnectionListResAck": "UE-associatedLogicalS1-ConnectionItemResAck",
}

var protocolExtensionFieldObjectSets = map[string]string{
	"AdditionalGUTI.IEExtensions":                                "Additional-GUTI-ExtIEs",
	"AllocationAndRetentionPriority.IEExtensions":                "AllocationAndRetentionPriority-ExtIEs",
	"AssistanceDataForCECapableUEs.IEExtensions":                 "InformationForCECapableUEs-ExtIEs",
	"AssistanceDataForPaging.IEExtensions":                       "AssistanceDataForPaging-ExtIEs",
	"AssistanceDataForRecommendedCells.IEExtensions":             "AssistanceDataForRecommendedCells-ExtIEs",
	"BearersSubjectToDLDiscardingItem.IEExtensions":              "Bearers-SubjectToDLDiscarding-ItemExtIEs",
	"BearersSubjectToEarlyStatusTransferItem.IEExtensions":       "Bearers-SubjectToEarlyStatusTransfer-ItemExtIEs",
	"BearersSubjectToStatusTransferItem.IEExtensions":            "Bearers-SubjectToStatusTransfer-ItemExtIEs",
	"BluetoothMeasurementConfiguration.IEExtensions":             "BluetoothMeasurementConfiguration-ExtIEs",
	"CGI.IEExtensions":                                           "CGI-ExtIEs",
	"CNTypeRestrictionsItem.IEExtensions":                        "CNTypeRestrictions-Item-ExtIEs",
	"COUNTValueExtended.IEExtensions":                            "COUNTValueExtended-ExtIEs",
	"COUNTvalue.IEExtensions":                                    "COUNTvalue-ExtIEs",
	"COUNTvaluePDCPSNlength18.IEExtensions":                      "COUNTvaluePDCP-SNlength18-ExtIEs",
	"CSGIdListItem.IEExtensions":                                 "CSG-IdList-Item-ExtIEs",
	"CSGMembershipInfo.IEExtensions":                             "CSGMembershipInfo-ExtIEs",
	"CancelledCellinEAIItem.IEExtensions":                        "CancelledCellinEAI-Item-ExtIEs",
	"CancelledCellinTAIItem.IEExtensions":                        "CancelledCellinTAI-Item-ExtIEs",
	"Cdma2000OneXSRVCCInfo.IEExtensions":                         "Cdma2000OneXSRVCCInfo-ExtIEs",
	"CellBasedMDT.IEExtensions":                                  "CellBasedMDT-ExtIEs",
	"CellBasedQMC.IEExtensions":                                  "CellBasedQMC-ExtIEs",
	"CellIDBroadcastItem.IEExtensions":                           "CellID-Broadcast-Item-ExtIEs",
	"CellIDCancelledItem.IEExtensions":                           "CellID-Cancelled-Item-ExtIEs",
	"CellIdentifierAndCELevelForCECapableUEs.IEExtensions":       "CellIdentifierAndCELevelForCECapableUEs-ExtIEs",
	"CellType.IEExtensions":                                      "CellType-ExtIEs",
	"CompletedCellinEAIItem.IEExtensions":                        "CompletedCellinEAI-Item-ExtIEs",
	"CompletedCellinTAIItem.IEExtensions":                        "CompletedCellinTAI-Item-ExtIEs",
	"ConnectedengNBItem.IEExtensions":                            "ConnectedengNBItem-ExtIEs",
	"ContextatSource.IEExtensions":                               "ContextatSource-ExtIEs",
	"CriticalityDiagnostics.IEExtensions":                        "CriticalityDiagnostics-ExtIEs",
	"CriticalityDiagnosticsIEItem.IEExtensions":                  "CriticalityDiagnostics-IE-Item-ExtIEs",
	"DAPSRequestInfo.IEExtensions":                               "DAPSRequestInfo-ExtIEs",
	"DAPSResponseInfo.IEExtensions":                              "DAPSResponseInfo-ExtIEs",
	"DAPSResponseInfoItem.IEExtensions":                          "DAPSResponseInfoItem-ExtIEs",
	"DLCPSecurityInformation.IEExtensions":                       "DL-CP-SecurityInformation-ExtIEs",
	"ENBEarlyStatusTransferTransparentContainer.IEExtensions":    "ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs",
	"ENBStatusTransferTransparentContainer.IEExtensions":         "ENB-StatusTransfer-TransparentContainer-ExtIEs",
	"ENBX2ExtTLA.IEExtensions":                                   "ENBX2ExtTLA-ExtIEs",
	"ENDCSONConfigurationTransfer.IEExtensions":                  "EN-DCSONConfigurationTransfer-ExtIEs",
	"ENDCSONeNBIdentification.IEExtensions":                      "EN-DCSONeNBIdentification-ExtIEs",
	"ENDCSONengNBIdentification.IEExtensions":                    "EN-DCSONengNBIdentification-ExtIEs",
	"ENDCTransferTypeReply.IEExtensions":                         "EN-DCTransferTypeReply-ExtIEs",
	"ENDCTransferTypeRequest.IEExtensions":                       "EN-DCTransferTypeRequest-ExtIEs",
	"ERABAdmittedItem.IEExtensions":                              "E-RABAdmittedItem-ExtIEs",
	"ERABDataForwardingItem.IEExtensions":                        "E-RABDataForwardingItem-ExtIEs",
	"ERABFailedToResumeItemResumeReq.IEExtensions":               "E-RABFailedToResumeItemResumeReq-ExtIEs",
	"ERABFailedToResumeItemResumeRes.IEExtensions":               "E-RABFailedToResumeItemResumeRes-ExtIEs",
	"ERABFailedToSetupItemHOReqAck.IEExtensions":                 "E-RABFailedToSetupItemHOReqAckExtIEs",
	"ERABInformationListItem.IEExtensions":                       "E-RABInformationListItem-ExtIEs",
	"ERABItem.IEExtensions":                                      "E-RABItem-ExtIEs",
	"ERABLevelQoSParameters.IEExtensions":                        "E-RABQoSParameters-ExtIEs",
	"ERABModifyItemBearerModConf.IEExtensions":                   "E-RABModifyItemBearerModConfExtIEs",
	"ERABModifyItemBearerModRes.IEExtensions":                    "E-RABModifyItemBearerModResExtIEs",
	"ERABNotToBeModifiedItemBearerModInd.IEExtensions":           "E-RABNotToBeModifiedItemBearerModInd-ExtIEs",
	"ERABReleaseItemBearerRelComp.IEExtensions":                  "E-RABReleaseItemBearerRelCompExtIEs",
	"ERABSecurityResultItem.IEExtensions":                        "E-RABSecurityResultItem-ExtIEs",
	"ERABSetupItemBearerSURes.IEExtensions":                      "E-RABSetupItemBearerSUResExtIEs",
	"ERABSetupItemCtxtSURes.IEExtensions":                        "E-RABSetupItemCtxtSUResExtIEs",
	"ERABToBeModifiedItemBearerModInd.IEExtensions":              "E-RABToBeModifiedItemBearerModInd-ExtIEs",
	"ERABToBeModifiedItemBearerModReq.IEExtensions":              "E-RABToBeModifyItemBearerModReqExtIEs",
	"ERABToBeSetupItemBearerSUReq.IEExtensions":                  "E-RABToBeSetupItemBearerSUReqExtIEs",
	"ERABToBeSetupItemCtxtSUReq.IEExtensions":                    "E-RABToBeSetupItemCtxtSUReqExtIEs",
	"ERABToBeSetupItemHOReq.IEExtensions":                        "E-RABToBeSetupItemHOReq-ExtIEs",
	"ERABToBeSwitchedDLItem.IEExtensions":                        "E-RABToBeSwitchedDLItem-ExtIEs",
	"ERABToBeSwitchedULItem.IEExtensions":                        "E-RABToBeSwitchedULItem-ExtIEs",
	"ERABToBeUpdatedItem.IEExtensions":                           "E-RABToBeUpdatedItem-ExtIEs",
	"ERABUsageReportItem.IEExtensions":                           "E-RABUsageReportItem-ExtIEs",
	"EUTRANCGI.IEExtensions":                                     "EUTRAN-CGI-ExtIEs",
	"EmergencyAreaIDBroadcastItem.IEExtensions":                  "EmergencyAreaID-Broadcast-Item-ExtIEs",
	"EmergencyAreaIDCancelledItem.IEExtensions":                  "EmergencyAreaID-Cancelled-Item-ExtIEs",
	"EventL1LoggedMDTConfig.IEExtensions":                        "EventL1LoggedMDTConfig-ExtIEs",
	"ExpectedUEActivityBehaviour.IEExtensions":                   "ExpectedUEActivityBehaviour-ExtIEs",
	"ExpectedUEBehaviour.IEExtensions":                           "ExpectedUEBehaviour-ExtIEs",
	"FiveGSTAI.IEExtensions":                                     "FiveGSTAI-ExtIEs",
	"ForbiddenLAsItem.IEExtensions":                              "ForbiddenLAs-Item-ExtIEs",
	"ForbiddenTAsItem.IEExtensions":                              "ForbiddenTAs-Item-ExtIEs",
	"GBRQosInformation.IEExtensions":                             "GBR-QosInformation-ExtIEs",
	"GERANCellID.IEExtensions":                                   "GERAN-Cell-ID-ExtIEs",
	"GNB.IEExtensions":                                           "GNB-ExtIEs",
	"GUMMEI.IEExtensions":                                        "GUMMEI-ExtIEs",
	"GlobalENBID.IEExtensions":                                   "GlobalENB-ID-ExtIEs",
	"GlobalEnGNBID.IEExtensions":                                 "Global-en-gNB-ID-ExtIEs",
	"GlobalGNBID.IEExtensions":                                   "Global-GNB-ID-ExtIEs",
	"HandoverRestrictionList.IEExtensions":                       "HandoverRestrictionList-ExtIEs",
	"ImmediateMDT.IEExtensions":                                  "ImmediateMDT-ExtIEs",
	"InformationOnRecommendedCellsAndENBsForPaging.IEExtensions": "InformationOnRecommendedCellsAndENBsForPaging-ExtIEs",
	"InterSystemMeasurementItem.IEExtensions":                    "InterSystemMeasurementItem-ExtIEs",
	"InterSystemMeasurementParameters.IEExtensions":              "InterSystemMeasurementParameters-ExtIEs",
	"IntersystemMeasurementConfiguration.IEExtensions":           "IntersystemMeasurementConfiguration-ExtIEs",
	"LAI.IEExtensions":                                           "LAI-ExtIEs",
	"LTENTNTAIInformation.IEExtensions":                          "LTE-NTN-TAI-Information-ExtIEs",
	"LastVisitedEUTRANCellInformation.IEExtensions":              "LastVisitedEUTRANCellInformation-ExtIEs",
	"LastVisitedPSCellInformation.IEExtensions":                  "LastVisitedPSCellInformation-ExtIEs",
	"ListeningSubframePattern.IEExtensions":                      "ListeningSubframePattern-ExtIEs",
	"LoggedMBSFNMDT.IEExtensions":                                "LoggedMBSFNMDT-ExtIEs",
	"LoggedMDT.IEExtensions":                                     "LoggedMDT-ExtIEs",
	"M1PeriodicReporting.IEExtensions":                           "M1PeriodicReporting-ExtIEs",
	"M1ThresholdEventA2.IEExtensions":                            "M1ThresholdEventA2-ExtIEs",
	"M3Configuration.IEExtensions":                               "M3Configuration-ExtIEs",
	"M4Configuration.IEExtensions":                               "M4Configuration-ExtIEs",
	"M5Configuration.IEExtensions":                               "M5Configuration-ExtIEs",
	"M6Configuration.IEExtensions":                               "M6Configuration-ExtIEs",
	"M7Configuration.IEExtensions":                               "M7Configuration-ExtIEs",
	"MBSFNResultToLogInfo.IEExtensions":                          "MBSFN-ResultToLogInfo-ExtIEs",
	"MDTConfiguration.IEExtensions":                              "MDT-Configuration-ExtIEs",
	"MutingPatternInformation.IEExtensions":                      "MutingPatternInformation-ExtIEs",
	"NBIoTPagingEDRXInformation.IEExtensions":                    "NB-IoT-Paging-eDRXInformation-ExtIEs",
	"NGENB.IEExtensions":                                         "NG-eNB-ExtIEs",
	"NRCGI.IEExtensions":                                         "NR-CGI-ExtIEs",
	"NRUESecurityCapabilities.IEExtensions":                      "NRUESecurityCapabilities-ExtIEs",
	"NRUESidelinkAggregateMaximumBitrate.IEExtensions":           "NRUESidelinkAggregateMaximumBitrate-ExtIEs",
	"NRV2XServicesAuthorized.IEExtensions":                       "NRV2XServicesAuthorized-ExtIEs",
	"PC5FlowBitRates.IEExtensions":                               "PC5FlowBitRates-ExtIEs",
	"PC5QoSFlowItem.IEExtensions":                                "PC5QoSFlowItem-ExtIEs",
	"PC5QoSParameters.IEExtensions":                              "PC5QoSParameters-ExtIEs",
	"PLMNAreaBasedQMC.IEExtensions":                              "PLMNAreaBasedQMC-ExtIEs",
	"PSCellInformation.IEExtensions":                             "PSCellInformation-ExtIEs",
	"PagingAttemptInformation.IEExtensions":                      "PagingAttemptInformation-ExtIEs",
	"PagingEDRXInformation.IEExtensions":                         "Paging-eDRXInformation-ExtIEs",
	"ProSeAuthorized.IEExtensions":                               "ProSeAuthorized-ExtIEs",
	"RATRestrictionsItem.IEExtensions":                           "RAT-RestrictionsItem-ExtIEs",
	"RIMTransfer.IEExtensions":                                   "RIMTransfer-ExtIEs",
	"RLFReportInformation.IEExtensions":                          "RLFReportInformation-ExtIEs",
	"RecommendedCellItem.IEExtensions":                           "RecommendedCellsForPagingItem-ExtIEs",
	"RecommendedCellsForPaging.IEExtensions":                     "RecommendedCellsForPaging-ExtIEs",
	"RecommendedENBItem.IEExtensions":                            "RecommendedENBItem-ExtIEs",
	"RecommendedENBsForPaging.IEExtensions":                      "RecommendedENBsForPaging-ExtIEs",
	"RequestType.IEExtensions":                                   "RequestType-ExtIEs",
	"RequestedTNLInfo.IEExtensions":                              "RequestedTNLInfo-ExtIEs",
	"SONConfigurationTransfer.IEExtensions":                      "SONConfigurationTransfer-ExtIEs",
	"SONInformationReply.IEExtensions":                           "SONInformationReply-ExtIEs",
	"STMSI.IEExtensions":                                         "S-TMSI-ExtIEs",
	"ScheduledCommunicationTime.IEExtensions":                    "ScheduledCommunicationTime-ExtIEs",
	"SecondaryRATDataUsageReportItem.IEExtensions":               "SecondaryRATDataUsageReportItem-ExtIEs",
	"SecurityContext.IEExtensions":                               "SecurityContext-ExtIEs",
	"SecurityIndication.IEExtensions":                            "SecurityIndication-ExtIEs",
	"SecurityResult.IEExtensions":                                "SecurityResult-ExtIEs",
	"SensorMeasConfigNameItem.IEExtensions":                      "SensorMeasConfigNameItem-ExtIEs",
	"SensorMeasurementConfiguration.IEExtensions":                "SensorMeasurementConfiguration-ExtIEs",
	"ServedDCNsItem.IEExtensions":                                "ServedDCNsItem-ExtIEs",
	"ServedGUMMEIsItem.IEExtensions":                             "ServedGUMMEIsItem-ExtIEs",
	"SourceNgRanNodeID.IEExtensions":                             "SourceNgRanNode-ID-ExtIEs",
	"SourceeNBID.IEExtensions":                                   "SourceeNB-ID-ExtIEs",
	"SourceeNBToTargeteNBTransparentContainer.IEExtensions":      "SourceeNB-ToTargeteNB-TransparentContainer-ExtIEs",
	"SubscriptionBasedUEDifferentiationInfo.IEExtensions":        "Subscription-Based-UE-DifferentiationInfo-ExtIEs",
	"SupportedTAsItem.IEExtensions":                              "SupportedTAs-Item-ExtIEs",
	"SynchronisationInformation.IEExtensions":                    "SynchronisationInformation-ExtIEs",
	"TABasedMDT.IEExtensions":                                    "TABasedMDT-ExtIEs",
	"TABasedQMC.IEExtensions":                                    "TABasedQMC-ExtIEs",
	"TAI.IEExtensions":                                           "TAI-ExtIEs",
	"TAIBasedMDT.IEExtensions":                                   "TAIBasedMDT-ExtIEs",
	"TAIBasedQMC.IEExtensions":                                   "TAIBasedQMC-ExtIEs",
	"TAIBroadcastItem.IEExtensions":                              "TAI-Broadcast-Item-ExtIEs",
	"TAICancelledItem.IEExtensions":                              "TAI-Cancelled-Item-ExtIEs",
	"TAIItem.IEExtensions":                                       "TAIItemExtIEs",
	"TargetNgRanNodeID.IEExtensions":                             "TargetNgRanNode-ID-ExtIEs",
	"TargetRNCID.IEExtensions":                                   "TargetRNC-ID-ExtIEs",
	"TargeteNBID.IEExtensions":                                   "TargeteNB-ID-ExtIEs",
	"TargeteNBToSourceeNBTransparentContainer.IEExtensions":      "TargeteNB-ToSourceeNB-TransparentContainer-ExtIEs",
	"TimeBasedHandoverInformation.IEExtensions":                  "TimeBasedHandoverInformation-ExtIEs",
	"TimeSynchronisationInfo.IEExtensions":                       "TimeSynchronisationInfo-ExtIEs",
	"TraceActivation.IEExtensions":                               "TraceActivation-ExtIEs",
	"TunnelInformation.IEExtensions":                             "Tunnel-Information-ExtIEs",
	"UEAggregateMaximumBitrate.IEExtensions":                     "UEAggregate-MaximumBitrates-ExtIEs",
	"UEAppLayerMeasConfig.IEExtensions":                          "UEAppLayerMeasConfig-ExtIEs",
	"UEAssociatedLogicalS1ConnectionItem.IEExtensions":           "UE-associatedLogicalS1-ConnectionItemExtIEs",
	"UES1APIDPair.IEExtensions":                                  "UE-S1AP-ID-pair-ExtIEs",
	"UESecurityCapabilities.IEExtensions":                        "UESecurityCapabilities-ExtIEs",
	"UESidelinkAggregateMaximumBitrate.IEExtensions":             "UE-Sidelink-Aggregate-MaximumBitrates-ExtIEs",
	"ULCPSecurityInformation.IEExtensions":                       "UL-CP-SecurityInformation-ExtIEs",
	"UserLocationInformation.IEExtensions":                       "UserLocationInformation-ExtIEs",
	"V2XServicesAuthorized.IEExtensions":                         "V2XServicesAuthorized-ExtIEs",
	"WLANMeasurementConfiguration.IEExtensions":                  "WLANMeasurementConfiguration-ExtIEs",
	"WUSAssistanceInformation.IEExtensions":                      "WUS-Assistance-Information-ExtIEs",
	"X2TNLConfigurationInfo.IEExtensions":                        "X2TNLConfigurationInfo-ExtIEs",
}

var protocolExtensionTypeObjectSets = map[string]string{}

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
	case "ENB-EarlyStatusTransfer-TransparentContainer-ExtIEs":
		switch id {
		case 352:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "Bearers-SubjectToDLDiscarding-ItemIEs", typeName: "BearersSubjectToDLDiscardingList"}
		}
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

// DecodeProtocolIEFieldsRecursive decodes fields using an ASN.1 object set.
func DecodeProtocolIEFieldsRecursive(objectSet string, fields []ProtocolIEField) ([]DecodedProtocolIEField, error) {
	return decodeProtocolIEFieldsAt(objectSet, fields, objectSet, map[protocolOpenTypeVisit]bool{})
}

// DecodeProtocolExtensionFieldsRecursive decodes extension fields using their ASN.1 object-set context.
func DecodeProtocolExtensionFieldsRecursive(objectSet string, fields []ProtocolExtensionField) ([]DecodedProtocolExtensionField, error) {
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
		elemKind := value.Type().Elem().Kind()
		if elemKind != reflect.Struct && elemKind != reflect.Pointer && elemKind != reflect.Interface &&
			elemKind != reflect.Slice && elemKind != reflect.Array {
			return decodedProtocolFields{}, nil
		}
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

// DecodeValueRecursive decodes the selected S1APPDU outcome and every nested protocol open type.
func (v *S1APPDU) DecodeValueRecursive() (*DecodedProtocolValue, error) {
	if v == nil {
		return nil, fmt.Errorf("cannot recursively decode nil S1APPDU")
	}
	switch v.Choice {
	case S1APPDUChoiceInitiatingMessage:
		if v.InitiatingMessage == nil {
			return nil, fmt.Errorf("S1APPDU initiatingMessage alternative is nil")
		}
		return v.InitiatingMessage.DecodeValueRecursive()
	case S1APPDUChoiceSuccessfulOutcome:
		if v.SuccessfulOutcome == nil {
			return nil, fmt.Errorf("S1APPDU successfulOutcome alternative is nil")
		}
		return v.SuccessfulOutcome.DecodeValueRecursive()
	case S1APPDUChoiceUnsuccessfulOutcome:
		if v.UnsuccessfulOutcome == nil {
			return nil, fmt.Errorf("S1APPDU unsuccessfulOutcome alternative is nil")
		}
		return v.UnsuccessfulOutcome.DecodeValueRecursive()
	default:
		return nil, fmt.Errorf("unknown S1APPDU choice %d", v.Choice)
	}
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

// DecodeValue decodes the Value field of a ProtocolIE-Field from its ASN.1 object set and IE ID.
func (v *ProtocolIEField) DecodeValue(objectSet string) (interface{}, error) {
	return DecodeIEFieldValue(objectSet, int64(v.Id), v.Value.Bytes)
}

// DecodeValue decodes ExtensionValue based on its object-set context and extension ID.
func (v *ProtocolExtensionField) DecodeValue(objectSet string) (interface{}, error) {
	return DecodeExtensionFieldValue(objectSet, int64(v.Id), v.ExtensionValue.Bytes)
}
