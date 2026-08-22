// Code generated from ASN.1. DO NOT EDIT.

package x2ap

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
	case 0: // id-handoverPreparation
		var v HandoverRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverRequest: %w", err)
		}
		return &v, nil
	case 4: // id-snStatusTransfer
		var v SNStatusTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SNStatusTransfer: %w", err)
		}
		return &v, nil
	case 5: // id-uEContextRelease
		var v UEContextRelease
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UEContextRelease: %w", err)
		}
		return &v, nil
	case 1: // id-handoverCancel
		var v HandoverCancel
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverCancel: %w", err)
		}
		return &v, nil
	case 14: // id-handoverReport
		var v HandoverReport
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverReport: %w", err)
		}
		return &v, nil
	case 3: // id-errorIndication
		var v ErrorIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ErrorIndication: %w", err)
		}
		return &v, nil
	case 7: // id-reset
		var v ResetRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ResetRequest: %w", err)
		}
		return &v, nil
	case 6: // id-x2Setup
		var v X2SetupRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding X2SetupRequest: %w", err)
		}
		return &v, nil
	case 2: // id-loadIndication
		var v LoadInformation
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding LoadInformation: %w", err)
		}
		return &v, nil
	case 8: // id-eNBConfigurationUpdate
		var v ENBConfigurationUpdate
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENBConfigurationUpdate: %w", err)
		}
		return &v, nil
	case 9: // id-resourceStatusReportingInitiation
		var v ResourceStatusRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ResourceStatusRequest: %w", err)
		}
		return &v, nil
	case 10: // id-resourceStatusReporting
		var v ResourceStatusUpdate
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ResourceStatusUpdate: %w", err)
		}
		return &v, nil
	case 13: // id-rLFIndication
		var v RLFIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding RLFIndication: %w", err)
		}
		return &v, nil
	case 11: // id-privateMessage
		var v PrivateMessage
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding PrivateMessage: %w", err)
		}
		return &v, nil
	case 12: // id-mobilitySettingsChange
		var v MobilityChangeRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding MobilityChangeRequest: %w", err)
		}
		return &v, nil
	case 15: // id-cellActivation
		var v CellActivationRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding CellActivationRequest: %w", err)
		}
		return &v, nil
	case 16: // id-x2Release
		var v X2Release
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding X2Release: %w", err)
		}
		return &v, nil
	case 17: // id-x2APMessageTransfer
		var v X2APMessageTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding X2APMessageTransfer: %w", err)
		}
		return &v, nil
	case 19: // id-seNBAdditionPreparation
		var v SeNBAdditionRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SeNBAdditionRequest: %w", err)
		}
		return &v, nil
	case 20: // id-seNBReconfigurationCompletion
		var v SeNBReconfigurationComplete
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SeNBReconfigurationComplete: %w", err)
		}
		return &v, nil
	case 21: // id-meNBinitiatedSeNBModificationPreparation
		var v SeNBModificationRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SeNBModificationRequest: %w", err)
		}
		return &v, nil
	case 22: // id-seNBinitiatedSeNBModification
		var v SeNBModificationRequired
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SeNBModificationRequired: %w", err)
		}
		return &v, nil
	case 23: // id-meNBinitiatedSeNBRelease
		var v SeNBReleaseRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SeNBReleaseRequest: %w", err)
		}
		return &v, nil
	case 24: // id-seNBinitiatedSeNBRelease
		var v SeNBReleaseRequired
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SeNBReleaseRequired: %w", err)
		}
		return &v, nil
	case 25: // id-seNBCounterCheck
		var v SeNBCounterCheckRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SeNBCounterCheckRequest: %w", err)
		}
		return &v, nil
	case 18: // id-x2Removal
		var v X2RemovalRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding X2RemovalRequest: %w", err)
		}
		return &v, nil
	case 26: // id-retrieveUEContext
		var v RetrieveUEContextRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding RetrieveUEContextRequest: %w", err)
		}
		return &v, nil
	case 27: // id-sgNBAdditionPreparation
		var v SgNBAdditionRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBAdditionRequest: %w", err)
		}
		return &v, nil
	case 28: // id-sgNBReconfigurationCompletion
		var v SgNBReconfigurationComplete
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBReconfigurationComplete: %w", err)
		}
		return &v, nil
	case 29: // id-meNBinitiatedSgNBModificationPreparation
		var v SgNBModificationRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBModificationRequest: %w", err)
		}
		return &v, nil
	case 30: // id-sgNBinitiatedSgNBModification
		var v SgNBModificationRequired
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBModificationRequired: %w", err)
		}
		return &v, nil
	case 31: // id-meNBinitiatedSgNBRelease
		var v SgNBReleaseRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBReleaseRequest: %w", err)
		}
		return &v, nil
	case 32: // id-sgNBinitiatedSgNBRelease
		var v SgNBReleaseRequired
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBReleaseRequired: %w", err)
		}
		return &v, nil
	case 33: // id-sgNBCounterCheck
		var v SgNBCounterCheckRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBCounterCheckRequest: %w", err)
		}
		return &v, nil
	case 34: // id-sgNBChange
		var v SgNBChangeRequired
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBChangeRequired: %w", err)
		}
		return &v, nil
	case 35: // id-rRCTransfer
		var v RRCTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding RRCTransfer: %w", err)
		}
		return &v, nil
	case 36: // id-endcX2Setup
		var v ENDCX2SetupRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCX2SetupRequest: %w", err)
		}
		return &v, nil
	case 37: // id-endcConfigurationUpdate
		var v ENDCConfigurationUpdate
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCConfigurationUpdate: %w", err)
		}
		return &v, nil
	case 38: // id-secondaryRATDataUsageReport
		var v SecondaryRATDataUsageReport
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SecondaryRATDataUsageReport: %w", err)
		}
		return &v, nil
	case 39: // id-endcCellActivation
		var v ENDCCellActivationRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCCellActivationRequest: %w", err)
		}
		return &v, nil
	case 40: // id-endcPartialReset
		var v ENDCPartialResetRequired
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCPartialResetRequired: %w", err)
		}
		return &v, nil
	case 41: // id-eUTRANRCellResourceCoordination
		var v EUTRANRCellResourceCoordinationRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding EUTRANRCellResourceCoordinationRequest: %w", err)
		}
		return &v, nil
	case 42: // id-SgNBActivityNotification
		var v SgNBActivityNotification
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBActivityNotification: %w", err)
		}
		return &v, nil
	case 43: // id-endcX2Removal
		var v ENDCX2RemovalRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCX2RemovalRequest: %w", err)
		}
		return &v, nil
	case 44: // id-dataForwardingAddressIndication
		var v DataForwardingAddressIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding DataForwardingAddressIndication: %w", err)
		}
		return &v, nil
	case 45: // id-gNBStatusIndication
		var v GNBStatusIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding GNBStatusIndication: %w", err)
		}
		return &v, nil
	case 48: // id-endcConfigurationTransfer
		var v ENDCConfigurationTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCConfigurationTransfer: %w", err)
		}
		return &v, nil
	case 46: // id-deactivateTrace
		var v DeactivateTrace
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding DeactivateTrace: %w", err)
		}
		return &v, nil
	case 47: // id-traceStart
		var v TraceStart
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding TraceStart: %w", err)
		}
		return &v, nil
	case 49: // id-handoverSuccess
		var v HandoverSuccess
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverSuccess: %w", err)
		}
		return &v, nil
	case 51: // id-earlyStatusTransfer
		var v EarlyStatusTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding EarlyStatusTransfer: %w", err)
		}
		return &v, nil
	case 50: // id-conditionalHandoverCancel
		var v ConditionalHandoverCancel
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ConditionalHandoverCancel: %w", err)
		}
		return &v, nil
	case 54: // id-endcresourceStatusReportingInitiation
		var v ENDCResourceStatusRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCResourceStatusRequest: %w", err)
		}
		return &v, nil
	case 53: // id-endcresourceStatusReporting
		var v ENDCResourceStatusUpdate
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCResourceStatusUpdate: %w", err)
		}
		return &v, nil
	case 52: // id-cellTrafficTrace
		var v CellTrafficTrace
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding CellTrafficTrace: %w", err)
		}
		return &v, nil
	case 55: // id-f1CTrafficTransfer
		var v F1CTrafficTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding F1CTrafficTransfer: %w", err)
		}
		return &v, nil
	case 56: // id-UERadioCapabilityIDMapping
		var v UERadioCapabilityIDMappingRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UERadioCapabilityIDMappingRequest: %w", err)
		}
		return &v, nil
	case 57: // id-accessAndMobilityIndication
		var v AccessAndMobilityIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding AccessAndMobilityIndication: %w", err)
		}
		return &v, nil
	case 59: // id-CPC-cancel
		var v CPCCancel
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding CPCCancel: %w", err)
		}
		return &v, nil
	case 60: // id-rachIndication
		var v RachIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding RachIndication: %w", err)
		}
		return &v, nil
	case 61: // id-scgFailureInformationReport
		var v SCGFailureInformationReport
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SCGFailureInformationReport: %w", err)
		}
		return &v, nil
	case 62: // id-scgFailureTransfer
		var v SCGFailureTransfer
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SCGFailureTransfer: %w", err)
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
	case 0: // id-handoverPreparation
		var v HandoverRequestAcknowledge
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverRequestAcknowledge: %w", err)
		}
		return &v, nil
	case 7: // id-reset
		var v ResetResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ResetResponse: %w", err)
		}
		return &v, nil
	case 6: // id-x2Setup
		var v X2SetupResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding X2SetupResponse: %w", err)
		}
		return &v, nil
	case 8: // id-eNBConfigurationUpdate
		var v ENBConfigurationUpdateAcknowledge
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENBConfigurationUpdateAcknowledge: %w", err)
		}
		return &v, nil
	case 9: // id-resourceStatusReportingInitiation
		var v ResourceStatusResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ResourceStatusResponse: %w", err)
		}
		return &v, nil
	case 12: // id-mobilitySettingsChange
		var v MobilityChangeAcknowledge
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding MobilityChangeAcknowledge: %w", err)
		}
		return &v, nil
	case 15: // id-cellActivation
		var v CellActivationResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding CellActivationResponse: %w", err)
		}
		return &v, nil
	case 19: // id-seNBAdditionPreparation
		var v SeNBAdditionRequestAcknowledge
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SeNBAdditionRequestAcknowledge: %w", err)
		}
		return &v, nil
	case 21: // id-meNBinitiatedSeNBModificationPreparation
		var v SeNBModificationRequestAcknowledge
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SeNBModificationRequestAcknowledge: %w", err)
		}
		return &v, nil
	case 22: // id-seNBinitiatedSeNBModification
		var v SeNBModificationConfirm
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SeNBModificationConfirm: %w", err)
		}
		return &v, nil
	case 24: // id-seNBinitiatedSeNBRelease
		var v SeNBReleaseConfirm
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SeNBReleaseConfirm: %w", err)
		}
		return &v, nil
	case 18: // id-x2Removal
		var v X2RemovalResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding X2RemovalResponse: %w", err)
		}
		return &v, nil
	case 26: // id-retrieveUEContext
		var v RetrieveUEContextResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding RetrieveUEContextResponse: %w", err)
		}
		return &v, nil
	case 27: // id-sgNBAdditionPreparation
		var v SgNBAdditionRequestAcknowledge
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBAdditionRequestAcknowledge: %w", err)
		}
		return &v, nil
	case 29: // id-meNBinitiatedSgNBModificationPreparation
		var v SgNBModificationRequestAcknowledge
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBModificationRequestAcknowledge: %w", err)
		}
		return &v, nil
	case 30: // id-sgNBinitiatedSgNBModification
		var v SgNBModificationConfirm
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBModificationConfirm: %w", err)
		}
		return &v, nil
	case 31: // id-meNBinitiatedSgNBRelease
		var v SgNBReleaseRequestAcknowledge
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBReleaseRequestAcknowledge: %w", err)
		}
		return &v, nil
	case 32: // id-sgNBinitiatedSgNBRelease
		var v SgNBReleaseConfirm
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBReleaseConfirm: %w", err)
		}
		return &v, nil
	case 34: // id-sgNBChange
		var v SgNBChangeConfirm
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBChangeConfirm: %w", err)
		}
		return &v, nil
	case 36: // id-endcX2Setup
		var v ENDCX2SetupResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCX2SetupResponse: %w", err)
		}
		return &v, nil
	case 37: // id-endcConfigurationUpdate
		var v ENDCConfigurationUpdateAcknowledge
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCConfigurationUpdateAcknowledge: %w", err)
		}
		return &v, nil
	case 39: // id-endcCellActivation
		var v ENDCCellActivationResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCCellActivationResponse: %w", err)
		}
		return &v, nil
	case 40: // id-endcPartialReset
		var v ENDCPartialResetConfirm
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCPartialResetConfirm: %w", err)
		}
		return &v, nil
	case 41: // id-eUTRANRCellResourceCoordination
		var v EUTRANRCellResourceCoordinationResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding EUTRANRCellResourceCoordinationResponse: %w", err)
		}
		return &v, nil
	case 43: // id-endcX2Removal
		var v ENDCX2RemovalResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCX2RemovalResponse: %w", err)
		}
		return &v, nil
	case 54: // id-endcresourceStatusReportingInitiation
		var v ENDCResourceStatusResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCResourceStatusResponse: %w", err)
		}
		return &v, nil
	case 56: // id-UERadioCapabilityIDMapping
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
	case 0: // id-handoverPreparation
		var v HandoverPreparationFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding HandoverPreparationFailure: %w", err)
		}
		return &v, nil
	case 6: // id-x2Setup
		var v X2SetupFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding X2SetupFailure: %w", err)
		}
		return &v, nil
	case 8: // id-eNBConfigurationUpdate
		var v ENBConfigurationUpdateFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENBConfigurationUpdateFailure: %w", err)
		}
		return &v, nil
	case 9: // id-resourceStatusReportingInitiation
		var v ResourceStatusFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ResourceStatusFailure: %w", err)
		}
		return &v, nil
	case 12: // id-mobilitySettingsChange
		var v MobilityChangeFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding MobilityChangeFailure: %w", err)
		}
		return &v, nil
	case 15: // id-cellActivation
		var v CellActivationFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding CellActivationFailure: %w", err)
		}
		return &v, nil
	case 19: // id-seNBAdditionPreparation
		var v SeNBAdditionRequestReject
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SeNBAdditionRequestReject: %w", err)
		}
		return &v, nil
	case 21: // id-meNBinitiatedSeNBModificationPreparation
		var v SeNBModificationRequestReject
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SeNBModificationRequestReject: %w", err)
		}
		return &v, nil
	case 22: // id-seNBinitiatedSeNBModification
		var v SeNBModificationRefuse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SeNBModificationRefuse: %w", err)
		}
		return &v, nil
	case 18: // id-x2Removal
		var v X2RemovalFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding X2RemovalFailure: %w", err)
		}
		return &v, nil
	case 26: // id-retrieveUEContext
		var v RetrieveUEContextFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding RetrieveUEContextFailure: %w", err)
		}
		return &v, nil
	case 27: // id-sgNBAdditionPreparation
		var v SgNBAdditionRequestReject
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBAdditionRequestReject: %w", err)
		}
		return &v, nil
	case 29: // id-meNBinitiatedSgNBModificationPreparation
		var v SgNBModificationRequestReject
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBModificationRequestReject: %w", err)
		}
		return &v, nil
	case 30: // id-sgNBinitiatedSgNBModification
		var v SgNBModificationRefuse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBModificationRefuse: %w", err)
		}
		return &v, nil
	case 31: // id-meNBinitiatedSgNBRelease
		var v SgNBReleaseRequestReject
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBReleaseRequestReject: %w", err)
		}
		return &v, nil
	case 34: // id-sgNBChange
		var v SgNBChangeRefuse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding SgNBChangeRefuse: %w", err)
		}
		return &v, nil
	case 36: // id-endcX2Setup
		var v ENDCX2SetupFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCX2SetupFailure: %w", err)
		}
		return &v, nil
	case 37: // id-endcConfigurationUpdate
		var v ENDCConfigurationUpdateFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCConfigurationUpdateFailure: %w", err)
		}
		return &v, nil
	case 39: // id-endcCellActivation
		var v ENDCCellActivationFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCCellActivationFailure: %w", err)
		}
		return &v, nil
	case 43: // id-endcX2Removal
		var v ENDCX2RemovalFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCX2RemovalFailure: %w", err)
		}
		return &v, nil
	case 54: // id-endcresourceStatusReportingInitiation
		var v ENDCResourceStatusFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ENDCResourceStatusFailure: %w", err)
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
	case "ERABItem", "E-RAB-ItemIEs":
		switch ieId {
		case 2: // id-E-RAB-Item -> E-RAB-Item
			var v ERABItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE E-RAB-Item (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABUsageReportItem", "E-RABUsageReport-ItemIEs":
		switch ieId {
		case 263: // id-E-RABUsageReport-Item -> E-RABUsageReport-Item
			var v ERABUsageReportItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE E-RABUsageReport-Item (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SecondaryRATUsageReportItem", "SecondaryRATUsageReport-ItemIEs":
		switch ieId {
		case 266: // id-SecondaryRATUsageReport-Item -> SecondaryRATUsageReport-Item
			var v SecondaryRATUsageReportItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SecondaryRATUsageReport-Item (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverRequest", "HandoverRequest-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 11: // id-TargetCell-ID -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 23: // id-GUMMEI-ID -> GUMMEI
			var v GUMMEI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GUMMEI (%d): %w", ieId, err)
			}
			return &v, nil
		case 14: // id-UE-ContextInformation -> UEContextInformation
			var v UEContextInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEContextInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 15: // id-UE-HistoryInformation -> UE-HistoryInformation (SEQUENCE OF LastVisitedCellItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-HistoryInformation length: %w", err)
			}
			result := make(UEHistoryInformation, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE UE-HistoryInformation item %d: %w", i, err)
				}
			}
			return &result, nil
		case 13: // id-TraceActivation -> TraceActivation
			var v TraceActivation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TraceActivation (%d): %w", ieId, err)
			}
			return &v, nil
		case 36: // id-SRVCCOperationPossible -> SRVCCOperationPossible (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SRVCCOperationPossible (%d): %w", ieId, err)
			}
			result := SRVCCOperationPossible(v)
			return &result, nil
		case 71: // id-CSGMembershipStatus -> CSGMembershipStatus (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGMembershipStatus (%d): %w", ieId, err)
			}
			result := CSGMembershipStatus(v)
			return &result, nil
		case 82: // id-MobilityInformation -> MobilityInformation (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MobilityInformation (%d): %w", ieId, err)
			}
			result := MobilityInformation{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 98: // id-Masked-IMEISV -> Masked-IMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Masked-IMEISV (%d): %w", ieId, err)
			}
			result := MaskedIMEISV{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 105: // id-UE-HistoryInformationFromTheUE -> UE-HistoryInformationFromTheUE (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-HistoryInformationFromTheUE (%d): %w", ieId, err)
			}
			result := UEHistoryInformationFromTheUE(v)
			return &result, nil
		case 104: // id-ExpectedUEBehaviour -> ExpectedUEBehaviour
			var v ExpectedUEBehaviour
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ExpectedUEBehaviour (%d): %w", ieId, err)
			}
			return &v, nil
		case 103: // id-ProSeAuthorized -> ProSeAuthorized
			var v ProSeAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ProSeAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 153: // id-UE-ContextReferenceAtSeNB -> UEContextReferenceAtSeNB
			var v UEContextReferenceAtSeNB
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEContextReferenceAtSeNB (%d): %w", ieId, err)
			}
			return &v, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 176: // id-V2XServicesAuthorized -> V2XServicesAuthorized
			var v V2XServicesAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE V2XServicesAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 182: // id-UE-ContextReferenceAtWT -> UEContextReferenceAtWT
			var v UEContextReferenceAtWT
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEContextReferenceAtWT (%d): %w", ieId, err)
			}
			return &v, nil
		case 248: // id-NRUESecurityCapabilities -> NRUESecurityCapabilities
			var v NRUESecurityCapabilities
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRUESecurityCapabilities (%d): %w", ieId, err)
			}
			return &v, nil
		case 254: // id-UE-ContextReferenceAtSgNB -> UEContextReferenceAtSgNB
			var v UEContextReferenceAtSgNB
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEContextReferenceAtSgNB (%d): %w", ieId, err)
			}
			return &v, nil
		case 277: // id-AerialUEsubscriptionInformation -> AerialUEsubscriptionInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AerialUEsubscriptionInformation (%d): %w", ieId, err)
			}
			result := AerialUEsubscriptionInformation(v)
			return &result, nil
		case 309: // id-Subscription-Based-UE-DifferentiationInfo -> Subscription-Based-UE-DifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Subscription-Based-UE-DifferentiationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 361: // id-CHOinformation-REQ -> CHOinformation-REQ
			var v CHOinformationREQ
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CHOinformation-REQ (%d): %w", ieId, err)
			}
			return &v, nil
		case 370: // id-NRV2XServicesAuthorized -> NRV2XServicesAuthorized
			var v NRV2XServicesAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRV2XServicesAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 372: // id-PC5QoSParameters -> PC5QoSParameters
			var v PC5QoSParameters
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE PC5QoSParameters (%d): %w", ieId, err)
			}
			return &v, nil
		case 395: // id-IABNodeIndication -> IABNodeIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IABNodeIndication (%d): %w", ieId, err)
			}
			result := IABNodeIndication(v)
			return &result, nil
		}
	case "ERABsToBeSetupItem", "E-RABs-ToBeSetup-ItemIEs":
		switch ieId {
		case 4: // id-E-RABs-ToBeSetup-Item -> ERABsToBeSetupItem
			var v ERABsToBeSetupItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeSetupItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverRequestAcknowledge", "HandoverRequestAcknowledge-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 1: // id-E-RABs-Admitted-List -> ERABsAdmittedList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedList (%d): %w", ieId, err)
			}
			return &v, nil
		case 3: // id-E-RABs-NotAdmitted-List -> E-RAB-List (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RAB-List (%d): %w", ieId, err)
			}
			return &v, nil
		case 12: // id-TargeteNBtoSource-eNBTransparentContainer -> TargeteNBtoSource-eNBTransparentContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TargeteNBtoSource-eNBTransparentContainer (%d): %w", ieId, err)
			}
			result := TargeteNBtoSourceENBTransparentContainer(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 154: // id-UE-ContextKeptIndicator -> UE-ContextKeptIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-ContextKeptIndicator (%d): %w", ieId, err)
			}
			result := UEContextKeptIndicator(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 183: // id-WT-UE-ContextKeptIndicator -> UE-ContextKeptIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-ContextKeptIndicator (%d): %w", ieId, err)
			}
			result := UEContextKeptIndicator(v)
			return &result, nil
		case 339: // id-ERABs-transferred-to-MeNB -> E-RAB-List (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RAB-List (%d): %w", ieId, err)
			}
			return &v, nil
		case 362: // id-CHOinformation-ACK -> CHOinformation-ACK
			var v CHOinformationACK
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CHOinformation-ACK (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsAdmittedItem", "E-RABs-Admitted-ItemIEs":
		switch ieId {
		case 0: // id-E-RABs-Admitted-Item -> ERABsAdmittedItem
			var v ERABsAdmittedItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverPreparationFailure", "HandoverPreparationFailure-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 364: // id-RequestedTargetCellID -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverReport", "HandoverReport-IEs":
		switch ieId {
		case 54: // id-HandoverReportType -> HandoverReportType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE HandoverReportType (%d): %w", ieId, err)
			}
			result := HandoverReportType(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 52: // id-SourceCellECGI -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 53: // id-FailureCellECGI -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 49: // id-Re-establishmentCellECGI -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 81: // id-TargetCellInUTRAN -> TargetCellInUTRAN (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TargetCellInUTRAN (%d): %w", ieId, err)
			}
			result := TargetCellInUTRAN(v)
			return &result, nil
		case 83: // id-SourceCellCRNTI -> CRNTI (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CRNTI (%d): %w", ieId, err)
			}
			result := CRNTI{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 82: // id-MobilityInformation -> MobilityInformation (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MobilityInformation (%d): %w", ieId, err)
			}
			result := MobilityInformation{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 60: // id-UE-RLF-Report-Container -> UE-RLF-Report-Container (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-RLF-Report-Container (%d): %w", ieId, err)
			}
			result := UERLFReportContainer(v)
			return &result, nil
		case 107: // id-UE-RLF-Report-Container-for-extended-bands -> UE-RLF-Report-Container-for-extended-bands (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-RLF-Report-Container-for-extended-bands (%d): %w", ieId, err)
			}
			result := UERLFReportContainerForExtendedBands(v)
			return &result, nil
		case 382: // id-TargetCellInNGRAN -> TargetCellInNGRAN (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TargetCellInNGRAN (%d): %w", ieId, err)
			}
			result := TargetCellInNGRAN(v)
			return &result, nil
		}
	case "EarlyStatusTransfer", "EarlyStatusTransfer-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 367: // id-ProcedureStage -> ProcedureStageChoice
			var v ProcedureStageChoice
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ProcedureStageChoice (%d): %w", ieId, err)
			}
			return &v, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		}
	case "SNStatusTransfer", "SNStatusTransfer-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 18: // id-E-RABs-SubjectToStatusTransfer-List -> ERABsSubjectToStatusTransferList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsSubjectToStatusTransferList (%d): %w", ieId, err)
			}
			return &v, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		}
	case "ERABsSubjectToStatusTransferItem", "E-RABs-SubjectToStatusTransfer-ItemIEs":
		switch ieId {
		case 19: // id-E-RABs-SubjectToStatusTransfer-Item -> ERABsSubjectToStatusTransferItem
			var v ERABsSubjectToStatusTransferItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsSubjectToStatusTransferItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextRelease", "UEContextRelease-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 164: // id-SIPTO-BearerDeactivationIndication -> SIPTOBearerDeactivationIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SIPTOBearerDeactivationIndication (%d): %w", ieId, err)
			}
			result := SIPTOBearerDeactivationIndication(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		}
	case "HandoverCancel", "HandoverCancel-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 365: // id-CandidateCellsToBeCancelledList -> CandidateCellsToBeCancelledList (SEQUENCE OF ECGI)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 8)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CandidateCellsToBeCancelledList length: %w", err)
			}
			result := make(CandidateCellsToBeCancelledList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE CandidateCellsToBeCancelledList item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "HandoverSuccess", "HandoverSuccess-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 11: // id-TargetCell-ID -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ConditionalHandoverCancel", "ConditionalHandoverCancel-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 365: // id-CandidateCellsToBeCancelledList -> CandidateCellsToBeCancelledList (SEQUENCE OF ECGI)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 8)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CandidateCellsToBeCancelledList length: %w", err)
			}
			result := make(CandidateCellsToBeCancelledList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE CandidateCellsToBeCancelledList item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "ErrorIndication", "ErrorIndication-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 264: // id-Old-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "ResetRequest", "ResetRequest-IEs":
		switch ieId {
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "ResetResponse", "ResetResponse-IEs":
		switch ieId {
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "X2SetupRequest", "X2SetupRequest-IEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENB-ID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		case 20: // id-ServedCells -> ServedCells (SEQUENCE OF ServedCellsElem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedCells length: %w", err)
			}
			result := make(ServedCells, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedCells item %d: %w", i, err)
				}
			}
			return &result, nil
		case 24: // id-GUGroupIDList -> GUGroupIDList (SEQUENCE OF GUGroupID)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GUGroupIDList length: %w", err)
			}
			result := make(GUGroupIDList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE GUGroupIDList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 159: // id-LHN-ID -> LHN-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 32, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LHN-ID (%d): %w", ieId, err)
			}
			result := LHNID(v)
			return &result, nil
		}
	case "X2SetupResponse", "X2SetupResponse-IEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENB-ID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		case 20: // id-ServedCells -> ServedCells (SEQUENCE OF ServedCellsElem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedCells length: %w", err)
			}
			result := make(ServedCells, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedCells item %d: %w", i, err)
				}
			}
			return &result, nil
		case 24: // id-GUGroupIDList -> GUGroupIDList (SEQUENCE OF GUGroupID)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GUGroupIDList length: %w", err)
			}
			result := make(GUGroupIDList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE GUGroupIDList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 159: // id-LHN-ID -> LHN-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 32, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LHN-ID (%d): %w", ieId, err)
			}
			result := LHNID(v)
			return &result, nil
		}
	case "X2SetupFailure", "X2SetupFailure-IEs":
		switch ieId {
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 22: // id-TimeToWait -> TimeToWait (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 6, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeToWait (%d): %w", ieId, err)
			}
			result := TimeToWait(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "LoadInformation", "LoadInformation-IEs":
		switch ieId {
		case 6: // id-CellInformation -> CellInformationList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellInformationList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CellInformationItem", "CellInformation-ItemIEs":
		switch ieId {
		case 7: // id-CellInformation-Item -> CellInformationItem
			var v CellInformationItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellInformationItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENBConfigurationUpdate", "ENBConfigurationUpdate-IEs":
		switch ieId {
		case 25: // id-ServedCellsToAdd -> ServedCells (SEQUENCE OF ServedCellsElem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedCells length: %w", err)
			}
			result := make(ServedCells, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedCells item %d: %w", i, err)
				}
			}
			return &result, nil
		case 26: // id-ServedCellsToModify -> ServedCellsToModify (SEQUENCE OF ServedCellsToModifyItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedCellsToModify length: %w", err)
			}
			result := make(ServedCellsToModify, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedCellsToModify item %d: %w", i, err)
				}
			}
			return &result, nil
		case 27: // id-ServedCellsToDelete -> OldECGIs (SEQUENCE OF ECGI)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE OldECGIs length: %w", err)
			}
			result := make(OldECGIs, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE OldECGIs item %d: %w", i, err)
				}
			}
			return &result, nil
		case 34: // id-GUGroupIDToAddList -> GUGroupIDList (SEQUENCE OF GUGroupID)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GUGroupIDList length: %w", err)
			}
			result := make(GUGroupIDList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE GUGroupIDList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 35: // id-GUGroupIDToDeleteList -> GUGroupIDList (SEQUENCE OF GUGroupID)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GUGroupIDList length: %w", err)
			}
			result := make(GUGroupIDList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE GUGroupIDList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 143: // id-CoverageModificationList -> CoverageModificationList (SEQUENCE OF CoverageModificationItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CoverageModificationList length: %w", err)
			}
			result := make(CoverageModificationList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE CoverageModificationList item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "ENBConfigurationUpdateAcknowledge", "ENBConfigurationUpdateAcknowledge-IEs":
		switch ieId {
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENBConfigurationUpdateFailure", "ENBConfigurationUpdateFailure-IEs":
		switch ieId {
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 22: // id-TimeToWait -> TimeToWait (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 6, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeToWait (%d): %w", ieId, err)
			}
			result := TimeToWait(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ResourceStatusRequest", "ResourceStatusRequest-IEs":
		switch ieId {
		case 39: // id-ENB1-Measurement-ID -> Measurement-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID (%d): %w", ieId, err)
			}
			result := MeasurementID(v)
			return &result, nil
		case 40: // id-ENB2-Measurement-ID -> Measurement-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID (%d): %w", ieId, err)
			}
			result := MeasurementID(v)
			return &result, nil
		case 28: // id-Registration-Request -> Registration-Request (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Registration-Request (%d): %w", ieId, err)
			}
			result := RegistrationRequest(v)
			return &result, nil
		case 38: // id-ReportCharacteristics -> ReportCharacteristics (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ReportCharacteristics (%d): %w", ieId, err)
			}
			result := ReportCharacteristics{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 29: // id-CellToReport -> CellToReportList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellToReportList (%d): %w", ieId, err)
			}
			return &v, nil
		case 30: // id-ReportingPeriodicity -> ReportingPeriodicity (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ReportingPeriodicity (%d): %w", ieId, err)
			}
			result := ReportingPeriodicity(v)
			return &result, nil
		case 64: // id-PartialSuccessIndicator -> PartialSuccessIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PartialSuccessIndicator (%d): %w", ieId, err)
			}
			result := PartialSuccessIndicator(v)
			return &result, nil
		case 109: // id-ReportingPeriodicityRSRPMR -> ReportingPeriodicityRSRPMR (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ReportingPeriodicityRSRPMR (%d): %w", ieId, err)
			}
			result := ReportingPeriodicityRSRPMR(v)
			return &result, nil
		case 145: // id-ReportingPeriodicityCSIR -> ReportingPeriodicityCSIR (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 5, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ReportingPeriodicityCSIR (%d): %w", ieId, err)
			}
			result := ReportingPeriodicityCSIR(v)
			return &result, nil
		}
	case "CellToReportItem", "CellToReport-ItemIEs":
		switch ieId {
		case 31: // id-CellToReport-Item -> CellToReportItem
			var v CellToReportItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellToReportItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ResourceStatusResponse", "ResourceStatusResponse-IEs":
		switch ieId {
		case 39: // id-ENB1-Measurement-ID -> Measurement-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID (%d): %w", ieId, err)
			}
			result := MeasurementID(v)
			return &result, nil
		case 40: // id-ENB2-Measurement-ID -> Measurement-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID (%d): %w", ieId, err)
			}
			result := MeasurementID(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 65: // id-MeasurementInitiationResult-List -> MeasurementInitiationResultList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementInitiationResultList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MeasurementInitiationResultItem", "MeasurementInitiationResult-ItemIEs":
		switch ieId {
		case 66: // id-MeasurementInitiationResult-Item -> MeasurementInitiationResultItem
			var v MeasurementInitiationResultItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementInitiationResultItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MeasurementFailureCauseItem", "MeasurementFailureCause-ItemIEs":
		switch ieId {
		case 67: // id-MeasurementFailureCause-Item -> MeasurementFailureCauseItem
			var v MeasurementFailureCauseItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementFailureCauseItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ResourceStatusFailure", "ResourceStatusFailure-IEs":
		switch ieId {
		case 39: // id-ENB1-Measurement-ID -> Measurement-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID (%d): %w", ieId, err)
			}
			result := MeasurementID(v)
			return &result, nil
		case 40: // id-ENB2-Measurement-ID -> Measurement-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID (%d): %w", ieId, err)
			}
			result := MeasurementID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 68: // id-CompleteFailureCauseInformation-List -> CompleteFailureCauseInformationList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CompleteFailureCauseInformationList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CompleteFailureCauseInformationItem", "CompleteFailureCauseInformation-ItemIEs":
		switch ieId {
		case 69: // id-CompleteFailureCauseInformation-Item -> CompleteFailureCauseInformationItem
			var v CompleteFailureCauseInformationItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CompleteFailureCauseInformationItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ResourceStatusUpdate", "ResourceStatusUpdate-IEs":
		switch ieId {
		case 39: // id-ENB1-Measurement-ID -> Measurement-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID (%d): %w", ieId, err)
			}
			result := MeasurementID(v)
			return &result, nil
		case 40: // id-ENB2-Measurement-ID -> Measurement-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID (%d): %w", ieId, err)
			}
			result := MeasurementID(v)
			return &result, nil
		case 32: // id-CellMeasurementResult -> CellMeasurementResultList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellMeasurementResultList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CellMeasurementResultItem", "CellMeasurementResult-ItemIEs":
		switch ieId {
		case 33: // id-CellMeasurementResult-Item -> CellMeasurementResultItem
			var v CellMeasurementResultItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellMeasurementResultItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MobilityChangeRequest", "MobilityChangeRequest-IEs":
		switch ieId {
		case 43: // id-ENB1-Cell-ID -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 44: // id-ENB2-Cell-ID -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 46: // id-ENB1-Mobility-Parameters -> MobilityParametersInformation
			var v MobilityParametersInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE MobilityParametersInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 45: // id-ENB2-Proposed-Mobility-Parameters -> MobilityParametersInformation
			var v MobilityParametersInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE MobilityParametersInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MobilityChangeAcknowledge", "MobilityChangeAcknowledge-IEs":
		switch ieId {
		case 43: // id-ENB1-Cell-ID -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 44: // id-ENB2-Cell-ID -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MobilityChangeFailure", "MobilityChangeFailure-IEs":
		switch ieId {
		case 43: // id-ENB1-Cell-ID -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 44: // id-ENB2-Cell-ID -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 47: // id-ENB2-Mobility-Parameters-Modification-Range -> MobilityParametersModificationRange
			var v MobilityParametersModificationRange
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE MobilityParametersModificationRange (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "RLFIndication", "RLFIndication-IEs":
		switch ieId {
		case 48: // id-FailureCellPCI -> PCI (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(503), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PCI (%d): %w", ieId, err)
			}
			result := PCI(v)
			return &result, nil
		case 49: // id-Re-establishmentCellECGI -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 50: // id-FailureCellCRNTI -> CRNTI (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CRNTI (%d): %w", ieId, err)
			}
			result := CRNTI{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 51: // id-ShortMAC-I -> ShortMAC-I (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ShortMAC-I (%d): %w", ieId, err)
			}
			result := ShortMACI{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 60: // id-UE-RLF-Report-Container -> UE-RLF-Report-Container (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-RLF-Report-Container (%d): %w", ieId, err)
			}
			result := UERLFReportContainer(v)
			return &result, nil
		case 75: // id-RRCConnSetupIndicator -> RRCConnSetupIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RRCConnSetupIndicator (%d): %w", ieId, err)
			}
			result := RRCConnSetupIndicator(v)
			return &result, nil
		case 78: // id-RRCConnReestabIndicator -> RRCConnReestabIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RRCConnReestabIndicator (%d): %w", ieId, err)
			}
			result := RRCConnReestabIndicator(v)
			return &result, nil
		case 107: // id-UE-RLF-Report-Container-for-extended-bands -> UE-RLF-Report-Container-for-extended-bands (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-RLF-Report-Container-for-extended-bands (%d): %w", ieId, err)
			}
			result := UERLFReportContainerForExtendedBands(v)
			return &result, nil
		case 374: // id-NBIoT-RLF-Report-Container -> NBIoT-RLF-Report-Container (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NBIoT-RLF-Report-Container (%d): %w", ieId, err)
			}
			result := NBIoTRLFReportContainer(v)
			return &result, nil
		}
	case "CellActivationRequest", "CellActivationRequest-IEs":
		switch ieId {
		case 57: // id-ServedCellsToActivate -> ServedCellsToActivate (SEQUENCE OF ServedCellsToActivateItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedCellsToActivate length: %w", err)
			}
			result := make(ServedCellsToActivate, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedCellsToActivate item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "CellActivationResponse", "CellActivationResponse-IEs":
		switch ieId {
		case 58: // id-ActivatedCellList -> ActivatedCellList (SEQUENCE OF ActivatedCellListItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ActivatedCellList length: %w", err)
			}
			result := make(ActivatedCellList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ActivatedCellList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CellActivationFailure", "CellActivationFailure-IEs":
		switch ieId {
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "X2Release", "X2Release-IEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENB-ID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "X2APMessageTransfer", "X2APMessageTransfer-IEs":
		switch ieId {
		case 101: // id-RNL-Header -> RNLHeader
			var v RNLHeader
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RNLHeader (%d): %w", ieId, err)
			}
			return &v, nil
		case 102: // id-x2APMessage -> X2APMessage (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE X2APMessage (%d): %w", ieId, err)
			}
			result := X2APMessage(v)
			return &result, nil
		}
	case "SeNBAdditionRequest", "SeNBAdditionRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 113: // id-UE-SecurityCapabilities -> UESecurityCapabilities
			var v UESecurityCapabilities
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UESecurityCapabilities (%d): %w", ieId, err)
			}
			return &v, nil
		case 114: // id-SeNBSecurityKey -> SeNBSecurityKey (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 256, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SeNBSecurityKey (%d): %w", ieId, err)
			}
			result := SeNBSecurityKey{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 115: // id-SeNBUEAggregateMaximumBitRate -> UEAggregateMaximumBitRate
			var v UEAggregateMaximumBitRate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEAggregateMaximumBitRate (%d): %w", ieId, err)
			}
			return &v, nil
		case 116: // id-ServingPLMN -> PLMN-Identity (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PLMN-Identity (%d): %w", ieId, err)
			}
			result := PLMNIdentity(v)
			return &result, nil
		case 117: // id-E-RABs-ToBeAdded-List -> ERABsToBeAddedList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeAddedList (%d): %w", ieId, err)
			}
			return &v, nil
		case 119: // id-MeNBtoSeNBContainer -> MeNBtoSeNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeNBtoSeNBContainer (%d): %w", ieId, err)
			}
			result := MeNBtoSeNBContainer(v)
			return &result, nil
		case 71: // id-CSGMembershipStatus -> CSGMembershipStatus (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGMembershipStatus (%d): %w", ieId, err)
			}
			result := CSGMembershipStatus(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 104: // id-ExpectedUEBehaviour -> ExpectedUEBehaviour
			var v ExpectedUEBehaviour
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ExpectedUEBehaviour (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "ERABsToBeAddedItem", "E-RABs-ToBeAdded-ItemIEs":
		switch ieId {
		case 118: // id-E-RABs-ToBeAdded-Item -> ERABsToBeAddedItem
			var v ERABsToBeAddedItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeAddedItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SeNBAdditionRequestAcknowledge", "SeNBAdditionRequestAcknowledge-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 120: // id-E-RABs-Admitted-ToBeAdded-List -> ERABsAdmittedToBeAddedList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeAddedList (%d): %w", ieId, err)
			}
			return &v, nil
		case 3: // id-E-RABs-NotAdmitted-List -> E-RAB-List (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RAB-List (%d): %w", ieId, err)
			}
			return &v, nil
		case 122: // id-SeNBtoMeNBContainer -> SeNBtoMeNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SeNBtoMeNBContainer (%d): %w", ieId, err)
			}
			result := SeNBtoMeNBContainer(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 165: // id-GW-TransportLayerAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TransportLayerAddress (%d): %w", ieId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 168: // id-SIPTO-L-GW-TransportLayerAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TransportLayerAddress (%d): %w", ieId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 163: // id-Tunnel-Information-for-BBF -> TunnelInformation
			var v TunnelInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TunnelInformation (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsAdmittedToBeAddedItem", "E-RABs-Admitted-ToBeAdded-ItemIEs":
		switch ieId {
		case 121: // id-E-RABs-Admitted-ToBeAdded-Item -> ERABsAdmittedToBeAddedItem
			var v ERABsAdmittedToBeAddedItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeAddedItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SeNBAdditionRequestReject", "SeNBAdditionRequestReject-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "SeNBReconfigurationComplete", "SeNBReconfigurationComplete-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 123: // id-ResponseInformationSeNBReconfComp -> ResponseInformationSeNBReconfComp
			var v ResponseInformationSeNBReconfComp
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ResponseInformationSeNBReconfComp (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "SeNBModificationRequest", "SeNBModificationRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 136: // id-SCGChangeIndication -> SCGChangeIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGChangeIndication (%d): %w", ieId, err)
			}
			result := SCGChangeIndication(v)
			return &result, nil
		case 116: // id-ServingPLMN -> PLMN-Identity (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PLMN-Identity (%d): %w", ieId, err)
			}
			result := PLMNIdentity(v)
			return &result, nil
		case 124: // id-UE-ContextInformationSeNBModReq -> UEContextInformationSeNBModReq
			var v UEContextInformationSeNBModReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEContextInformationSeNBModReq (%d): %w", ieId, err)
			}
			return &v, nil
		case 119: // id-MeNBtoSeNBContainer -> MeNBtoSeNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeNBtoSeNBContainer (%d): %w", ieId, err)
			}
			result := MeNBtoSeNBContainer(v)
			return &result, nil
		case 71: // id-CSGMembershipStatus -> CSGMembershipStatus (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CSGMembershipStatus (%d): %w", ieId, err)
			}
			result := CSGMembershipStatus(v)
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "ERABsToBeAddedModReqItem", "E-RABs-ToBeAdded-ModReqItemIEs":
		switch ieId {
		case 125: // id-E-RABs-ToBeAdded-ModReqItem -> ERABsToBeAddedModReqItem
			var v ERABsToBeAddedModReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeAddedModReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsToBeModifiedModReqItem", "E-RABs-ToBeModified-ModReqItemIEs":
		switch ieId {
		case 126: // id-E-RABs-ToBeModified-ModReqItem -> ERABsToBeModifiedModReqItem
			var v ERABsToBeModifiedModReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeModifiedModReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsToBeReleasedModReqItem", "E-RABs-ToBeReleased-ModReqItemIEs":
		switch ieId {
		case 127: // id-E-RABs-ToBeReleased-ModReqItem -> ERABsToBeReleasedModReqItem
			var v ERABsToBeReleasedModReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedModReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SeNBModificationRequestAcknowledge", "SeNBModificationRequestAcknowledge-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 128: // id-E-RABs-Admitted-ToBeAdded-ModAckList -> ERABsAdmittedToBeAddedModAckList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeAddedModAckList (%d): %w", ieId, err)
			}
			return &v, nil
		case 129: // id-E-RABs-Admitted-ToBeModified-ModAckList -> ERABsAdmittedToBeModifiedModAckList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeModifiedModAckList (%d): %w", ieId, err)
			}
			return &v, nil
		case 130: // id-E-RABs-Admitted-ToBeReleased-ModAckList -> ERABsAdmittedToBeReleasedModAckList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeReleasedModAckList (%d): %w", ieId, err)
			}
			return &v, nil
		case 3: // id-E-RABs-NotAdmitted-List -> E-RAB-List (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RAB-List (%d): %w", ieId, err)
			}
			return &v, nil
		case 122: // id-SeNBtoMeNBContainer -> SeNBtoMeNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SeNBtoMeNBContainer (%d): %w", ieId, err)
			}
			result := SeNBtoMeNBContainer(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "ERABsAdmittedToBeAddedModAckItem", "E-RABs-Admitted-ToBeAdded-ModAckItemIEs":
		switch ieId {
		case 131: // id-E-RABs-Admitted-ToBeAdded-ModAckItem -> ERABsAdmittedToBeAddedModAckItem
			var v ERABsAdmittedToBeAddedModAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeAddedModAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsAdmittedToBeModifiedModAckItem", "E-RABs-Admitted-ToBeModified-ModAckItemIEs":
		switch ieId {
		case 132: // id-E-RABs-Admitted-ToBeModified-ModAckItem -> ERABsAdmittedToBeModifiedModAckItem
			var v ERABsAdmittedToBeModifiedModAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeModifiedModAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsAdmittedToBeReleasedModAckItem", "E-RABs-Admitted-ToBeReleased-ModAckItemIEs":
		switch ieId {
		case 133: // id-E-RABs-Admitted-ToBeReleased-ModAckItem -> ERABsAdmittedToReleasedModAckItem
			var v ERABsAdmittedToReleasedModAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToReleasedModAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SeNBModificationRequestReject", "SeNBModificationRequestReject-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "SeNBModificationRequired", "SeNBModificationRequired-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 136: // id-SCGChangeIndication -> SCGChangeIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGChangeIndication (%d): %w", ieId, err)
			}
			result := SCGChangeIndication(v)
			return &result, nil
		case 134: // id-E-RABs-ToBeReleased-ModReqd -> ERABsToBeReleasedModReqd (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedModReqd (%d): %w", ieId, err)
			}
			return &v, nil
		case 122: // id-SeNBtoMeNBContainer -> SeNBtoMeNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SeNBtoMeNBContainer (%d): %w", ieId, err)
			}
			result := SeNBtoMeNBContainer(v)
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "ERABsToBeReleasedModReqdItem", "E-RABs-ToBeReleased-ModReqdItemIEs":
		switch ieId {
		case 135: // id-E-RABs-ToBeReleased-ModReqdItem -> ERABsToBeReleasedModReqdItem
			var v ERABsToBeReleasedModReqdItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedModReqdItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SeNBModificationConfirm", "SeNBModificationConfirm-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 119: // id-MeNBtoSeNBContainer -> MeNBtoSeNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeNBtoSeNBContainer (%d): %w", ieId, err)
			}
			result := MeNBtoSeNBContainer(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "SeNBModificationRefuse", "SeNBModificationRefuse-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 119: // id-MeNBtoSeNBContainer -> MeNBtoSeNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeNBtoSeNBContainer (%d): %w", ieId, err)
			}
			result := MeNBtoSeNBContainer(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "SeNBReleaseRequest", "SeNBReleaseRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 137: // id-E-RABs-ToBeReleased-List-RelReq -> ERABsToBeReleasedListRelReq (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedListRelReq (%d): %w", ieId, err)
			}
			return &v, nil
		case 154: // id-UE-ContextKeptIndicator -> UE-ContextKeptIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-ContextKeptIndicator (%d): %w", ieId, err)
			}
			result := UEContextKeptIndicator(v)
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 181: // id-MakeBeforeBreakIndicator -> MakeBeforeBreakIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MakeBeforeBreakIndicator (%d): %w", ieId, err)
			}
			result := MakeBeforeBreakIndicator(v)
			return &result, nil
		}
	case "ERABsToBeReleasedRelReqItem", "E-RABs-ToBeReleased-RelReqItemIEs":
		switch ieId {
		case 138: // id-E-RABs-ToBeReleased-RelReqItem -> ERABsToBeReleasedRelReqItem
			var v ERABsToBeReleasedRelReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedRelReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SeNBReleaseRequired", "SeNBReleaseRequired-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "SeNBReleaseConfirm", "SeNBReleaseConfirm-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 139: // id-E-RABs-ToBeReleased-List-RelConf -> ERABsToBeReleasedListRelConf (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedListRelConf (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "ERABsToBeReleasedRelConfItem", "E-RABs-ToBeReleased-RelConfItemIEs":
		switch ieId {
		case 140: // id-E-RABs-ToBeReleased-RelConfItem -> ERABsToBeReleasedRelConfItem
			var v ERABsToBeReleasedRelConfItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedRelConfItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SeNBCounterCheckRequest", "SeNBCounterCheckRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 141: // id-E-RABs-SubjectToCounterCheck-List -> ERABsSubjectToCounterCheckList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsSubjectToCounterCheckList (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "ERABsSubjectToCounterCheckItem", "E-RABs-SubjectToCounterCheckItemIEs":
		switch ieId {
		case 142: // id-E-RABs-SubjectToCounterCheckItem -> ERABsSubjectToCounterCheckItem
			var v ERABsSubjectToCounterCheckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsSubjectToCounterCheckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "X2RemovalRequest", "X2RemovalRequest-IEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENB-ID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		case 169: // id-X2RemovalThreshold -> X2BenefitValue (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(8), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE X2BenefitValue (%d): %w", ieId, err)
			}
			result := X2BenefitValue(v)
			return &result, nil
		}
	case "X2RemovalResponse", "X2RemovalResponse-IEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENB-ID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "X2RemovalFailure", "X2RemovalFailure-IEs":
		switch ieId {
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "RetrieveUEContextRequest", "RetrieveUEContextRequest-IEs":
		switch ieId {
		case 9: // id-New-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 172: // id-resumeID -> ResumeID
			var v ResumeID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ResumeID (%d): %w", ieId, err)
			}
			return &v, nil
		case 51: // id-ShortMAC-I -> ShortMAC-I (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ShortMAC-I (%d): %w", ieId, err)
			}
			result := ShortMACI{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 175: // id-NewEUTRANCellIdentifier -> EUTRANCellIdentifier (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 28, 28, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EUTRANCellIdentifier (%d): %w", ieId, err)
			}
			result := EUTRANCellIdentifier{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 50: // id-FailureCellCRNTI -> CRNTI (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CRNTI (%d): %w", ieId, err)
			}
			result := CRNTI{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 48: // id-FailureCellPCI -> PCI (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(503), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PCI (%d): %w", ieId, err)
			}
			result := PCI(v)
			return &result, nil
		}
	case "RetrieveUEContextResponse", "RetrieveUEContextResponse-IEs":
		switch ieId {
		case 9: // id-New-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 10: // id-Old-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 23: // id-GUMMEI-ID -> GUMMEI
			var v GUMMEI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GUMMEI (%d): %w", ieId, err)
			}
			return &v, nil
		case 173: // id-UE-ContextInformationRetrieve -> UEContextInformationRetrieve
			var v UEContextInformationRetrieve
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEContextInformationRetrieve (%d): %w", ieId, err)
			}
			return &v, nil
		case 13: // id-TraceActivation -> TraceActivation
			var v TraceActivation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TraceActivation (%d): %w", ieId, err)
			}
			return &v, nil
		case 36: // id-SRVCCOperationPossible -> SRVCCOperationPossible (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SRVCCOperationPossible (%d): %w", ieId, err)
			}
			result := SRVCCOperationPossible(v)
			return &result, nil
		case 98: // id-Masked-IMEISV -> Masked-IMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Masked-IMEISV (%d): %w", ieId, err)
			}
			result := MaskedIMEISV{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 104: // id-ExpectedUEBehaviour -> ExpectedUEBehaviour
			var v ExpectedUEBehaviour
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ExpectedUEBehaviour (%d): %w", ieId, err)
			}
			return &v, nil
		case 103: // id-ProSeAuthorized -> ProSeAuthorized
			var v ProSeAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ProSeAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 176: // id-V2XServicesAuthorized -> V2XServicesAuthorized
			var v V2XServicesAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE V2XServicesAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 277: // id-AerialUEsubscriptionInformation -> AerialUEsubscriptionInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AerialUEsubscriptionInformation (%d): %w", ieId, err)
			}
			result := AerialUEsubscriptionInformation(v)
			return &result, nil
		case 309: // id-Subscription-Based-UE-DifferentiationInfo -> Subscription-Based-UE-DifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Subscription-Based-UE-DifferentiationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 370: // id-NRV2XServicesAuthorized -> NRV2XServicesAuthorized
			var v NRV2XServicesAuthorized
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRV2XServicesAuthorized (%d): %w", ieId, err)
			}
			return &v, nil
		case 372: // id-PC5QoSParameters -> PC5QoSParameters
			var v PC5QoSParameters
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE PC5QoSParameters (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsToBeSetupRetrieveItem", "E-RABs-ToBeSetupRetrieve-ItemIEs":
		switch ieId {
		case 174: // id-E-RABs-ToBeSetupRetrieve-Item -> ERABsToBeSetupRetrieveItem
			var v ERABsToBeSetupRetrieveItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeSetupRetrieveItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "RetrieveUEContextFailure", "RetrieveUEContextFailure-IEs":
		switch ieId {
		case 9: // id-New-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBAdditionRequest", "SgNBAdditionRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 248: // id-NRUESecurityCapabilities -> NRUESecurityCapabilities
			var v NRUESecurityCapabilities
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRUESecurityCapabilities (%d): %w", ieId, err)
			}
			return &v, nil
		case 203: // id-SgNBSecurityKey -> SgNBSecurityKey (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 256, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBSecurityKey (%d): %w", ieId, err)
			}
			result := SgNBSecurityKey{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 204: // id-SgNBUEAggregateMaximumBitRate -> UEAggregateMaximumBitRate
			var v UEAggregateMaximumBitRate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEAggregateMaximumBitRate (%d): %w", ieId, err)
			}
			return &v, nil
		case 269: // id-SelectedPLMN -> PLMN-Identity (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PLMN-Identity (%d): %w", ieId, err)
			}
			result := PLMNIdentity(v)
			return &result, nil
		case 240: // id-HandoverRestrictionList -> HandoverRestrictionList
			var v HandoverRestrictionList
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE HandoverRestrictionList (%d): %w", ieId, err)
			}
			return &v, nil
		case 205: // id-E-RABs-ToBeAdded-SgNBAddReqList -> ERABsToBeAddedSgNBAddReqList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeAddedSgNBAddReqList (%d): %w", ieId, err)
			}
			return &v, nil
		case 206: // id-MeNBtoSgNBContainer -> MeNBtoSgNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeNBtoSgNBContainer (%d): %w", ieId, err)
			}
			result := MeNBtoSgNBContainer(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 104: // id-ExpectedUEBehaviour -> ExpectedUEBehaviour
			var v ExpectedUEBehaviour
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ExpectedUEBehaviour (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 208: // id-RequestedSplitSRBs -> SplitSRBs (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SplitSRBs (%d): %w", ieId, err)
			}
			result := SplitSRBs(v)
			return &result, nil
		case 257: // id-MeNBResourceCoordinationInformation -> MeNBResourceCoordinationInformation
			var v MeNBResourceCoordinationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE MeNBResourceCoordinationInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 278: // id-SGNB-Addition-Trigger-Ind -> SGNB-Addition-Trigger-Ind (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SGNB-Addition-Trigger-Ind (%d): %w", ieId, err)
			}
			result := SGNBAdditionTriggerInd(v)
			return &result, nil
		case 275: // id-SubscriberProfileIDforRFP -> SubscriberProfileIDforRFP (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(256), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SubscriberProfileIDforRFP (%d): %w", ieId, err)
			}
			result := SubscriberProfileIDforRFP(v)
			return &result, nil
		case 279: // id-MeNBCell-ID -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 329: // id-DesiredActNotificationLevel -> DesiredActNotificationLevel (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE DesiredActNotificationLevel (%d): %w", ieId, err)
			}
			result := DesiredActNotificationLevel(v)
			return &result, nil
		case 13: // id-TraceActivation -> TraceActivation
			var v TraceActivation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TraceActivation (%d): %w", ieId, err)
			}
			return &v, nil
		case 330: // id-LocationInformationSgNBReporting -> LocationInformationSgNBReporting (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LocationInformationSgNBReporting (%d): %w", ieId, err)
			}
			result := LocationInformationSgNBReporting(v)
			return &result, nil
		case 98: // id-Masked-IMEISV -> Masked-IMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Masked-IMEISV (%d): %w", ieId, err)
			}
			result := MaskedIMEISV{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 340: // id-AdditionalRRMPriorityIndex -> AdditionalRRMPriorityIndex (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AdditionalRRMPriorityIndex (%d): %w", ieId, err)
			}
			result := AdditionalRRMPriorityIndex{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 343: // id-RequestedFastMCGRecoveryViaSRB3 -> RequestedFastMCGRecoveryViaSRB3 (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RequestedFastMCGRecoveryViaSRB3 (%d): %w", ieId, err)
			}
			result := RequestedFastMCGRecoveryViaSRB3(v)
			return &result, nil
		case 359: // id-UEContextReferenceatSourceNGRAN -> RAN-UE-NGAP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RAN-UE-NGAP-ID (%d): %w", ieId, err)
			}
			result := RANUENGAPID(v)
			return &result, nil
		case 74: // id-ManagementBasedMDTallowed -> ManagementBasedMDTallowed (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ManagementBasedMDTallowed (%d): %w", ieId, err)
			}
			result := ManagementBasedMDTallowed(v)
			return &result, nil
		case 378: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityID (%d): %w", ieId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		case 395: // id-IABNodeIndication -> IABNodeIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IABNodeIndication (%d): %w", ieId, err)
			}
			result := IABNodeIndication(v)
			return &result, nil
		case 411: // id-sourceNG-RAN-node-id -> Global-RAN-NODE-ID
			var v GlobalRANNODEID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Global-RAN-NODE-ID (%d): %w", ieId, err)
			}
			return &v, nil
		case 15: // id-UE-HistoryInformation -> UE-HistoryInformation (SEQUENCE OF LastVisitedCellItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-HistoryInformation length: %w", err)
			}
			result := make(UEHistoryInformation, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE UE-HistoryInformation item %d: %w", i, err)
				}
			}
			return &result, nil
		case 105: // id-UE-HistoryInformationFromTheUE -> UE-HistoryInformationFromTheUE (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-HistoryInformationFromTheUE (%d): %w", ieId, err)
			}
			result := UEHistoryInformationFromTheUE(v)
			return &result, nil
		case 419: // id-PSCellChangeHistory -> PSCellChangeHistory (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PSCellChangeHistory (%d): %w", ieId, err)
			}
			result := PSCellChangeHistory(v)
			return &result, nil
		case 420: // id-CHOinformation-AddReq -> CHOinformation-AddReq
			var v CHOinformationAddReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CHOinformation-AddReq (%d): %w", ieId, err)
			}
			return &v, nil
		case 423: // id-SCGActivationRequest -> SCGActivationRequest (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGActivationRequest (%d): %w", ieId, err)
			}
			result := SCGActivationRequest(v)
			return &result, nil
		case 424: // id-CPAinformation-REQ -> CPAinformation-REQ
			var v CPAinformationREQ
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPAinformation-REQ (%d): %w", ieId, err)
			}
			return &v, nil
		case 449: // id-IABAuthorized -> IABAuthorized (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IABAuthorized (%d): %w", ieId, err)
			}
			result := IABAuthorized(v)
			return &result, nil
		}
	case "ERABsToBeAddedSgNBAddReqItem", "E-RABs-ToBeAdded-SgNBAddReq-ItemIEs":
		switch ieId {
		case 209: // id-E-RABs-ToBeAdded-SgNBAddReq-Item -> ERABsToBeAddedSgNBAddReqItem
			var v ERABsToBeAddedSgNBAddReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeAddedSgNBAddReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBAdditionRequestAcknowledge", "SgNBAdditionRequestAcknowledge-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 210: // id-E-RABs-Admitted-ToBeAdded-SgNBAddReqAckList -> ERABsAdmittedToBeAddedSgNBAddReqAckList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeAddedSgNBAddReqAckList (%d): %w", ieId, err)
			}
			return &v, nil
		case 3: // id-E-RABs-NotAdmitted-List -> E-RAB-List (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RAB-List (%d): %w", ieId, err)
			}
			return &v, nil
		case 211: // id-SgNBtoMeNBContainer -> SgNBtoMeNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBtoMeNBContainer (%d): %w", ieId, err)
			}
			result := SgNBtoMeNBContainer(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 212: // id-AdmittedSplitSRBs -> SplitSRBs (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SplitSRBs (%d): %w", ieId, err)
			}
			result := SplitSRBs(v)
			return &result, nil
		case 258: // id-SgNBResourceCoordinationInformation -> SgNBResourceCoordinationInformation
			var v SgNBResourceCoordinationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SgNBResourceCoordinationInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 272: // id-RRCConfigIndication -> RRC-Config-Ind (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RRC-Config-Ind (%d): %w", ieId, err)
			}
			result := RRCConfigInd(v)
			return &result, nil
		case 331: // id-LocationInformationSgNB -> LocationInformationSgNB
			var v LocationInformationSgNB
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LocationInformationSgNB (%d): %w", ieId, err)
			}
			return &v, nil
		case 344: // id-AvailableFastMCGRecoveryViaSRB3 -> AvailableFastMCGRecoveryViaSRB3 (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AvailableFastMCGRecoveryViaSRB3 (%d): %w", ieId, err)
			}
			result := AvailableFastMCGRecoveryViaSRB3(v)
			return &result, nil
		case 410: // id-DirectForwardingPathAvailability -> DirectForwardingPathAvailability (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE DirectForwardingPathAvailability (%d): %w", ieId, err)
			}
			result := DirectForwardingPathAvailability(v)
			return &result, nil
		case 422: // id-SCGActivationStatus -> SCGActivationStatus (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGActivationStatus (%d): %w", ieId, err)
			}
			result := SCGActivationStatus(v)
			return &result, nil
		case 425: // id-CPAinformation-REQ-ACK -> CPAinformation-REQ-ACK
			var v CPAinformationREQACK
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPAinformation-REQ-ACK (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsAdmittedToBeAddedSgNBAddReqAckItem", "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-ItemIEs":
		switch ieId {
		case 213: // id-E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item -> ERABsAdmittedToBeAddedSgNBAddReqAckItem
			var v ERABsAdmittedToBeAddedSgNBAddReqAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeAddedSgNBAddReqAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBAdditionRequestReject", "SgNBAdditionRequestReject-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "SgNBReconfigurationComplete", "SgNBReconfigurationComplete-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 214: // id-ResponseInformationSgNBReconfComp -> ResponseInformationSgNBReconfComp
			var v ResponseInformationSgNBReconfComp
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ResponseInformationSgNBReconfComp (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "SgNBModificationRequest", "SgNBModificationRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 269: // id-SelectedPLMN -> PLMN-Identity (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PLMN-Identity (%d): %w", ieId, err)
			}
			result := PLMNIdentity(v)
			return &result, nil
		case 240: // id-HandoverRestrictionList -> HandoverRestrictionList
			var v HandoverRestrictionList
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE HandoverRestrictionList (%d): %w", ieId, err)
			}
			return &v, nil
		case 241: // id-SCGConfigurationQuery -> SCGConfigurationQuery (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGConfigurationQuery (%d): %w", ieId, err)
			}
			result := SCGConfigurationQuery(v)
			return &result, nil
		case 215: // id-UE-ContextInformation-SgNBModReq -> UEContextInformationSgNBModReq
			var v UEContextInformationSgNBModReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE UEContextInformationSgNBModReq (%d): %w", ieId, err)
			}
			return &v, nil
		case 206: // id-MeNBtoSgNBContainer -> MeNBtoSgNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeNBtoSgNBContainer (%d): %w", ieId, err)
			}
			result := MeNBtoSgNBContainer(v)
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 257: // id-MeNBResourceCoordinationInformation -> MeNBResourceCoordinationInformation
			var v MeNBResourceCoordinationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE MeNBResourceCoordinationInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 208: // id-RequestedSplitSRBs -> SplitSRBs (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SplitSRBs (%d): %w", ieId, err)
			}
			result := SplitSRBs(v)
			return &result, nil
		case 280: // id-RequestedSplitSRBsrelease -> SplitSRBs (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SplitSRBs (%d): %w", ieId, err)
			}
			result := SplitSRBs(v)
			return &result, nil
		case 329: // id-DesiredActNotificationLevel -> DesiredActNotificationLevel (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE DesiredActNotificationLevel (%d): %w", ieId, err)
			}
			result := DesiredActNotificationLevel(v)
			return &result, nil
		case 330: // id-LocationInformationSgNBReporting -> LocationInformationSgNBReporting (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LocationInformationSgNBReporting (%d): %w", ieId, err)
			}
			result := LocationInformationSgNBReporting(v)
			return &result, nil
		case 279: // id-MeNBCell-ID -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 343: // id-RequestedFastMCGRecoveryViaSRB3 -> RequestedFastMCGRecoveryViaSRB3 (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RequestedFastMCGRecoveryViaSRB3 (%d): %w", ieId, err)
			}
			result := RequestedFastMCGRecoveryViaSRB3(v)
			return &result, nil
		case 345: // id-RequestedFastMCGRecoveryViaSRB3Release -> RequestedFastMCGRecoveryViaSRB3Release (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RequestedFastMCGRecoveryViaSRB3Release (%d): %w", ieId, err)
			}
			result := RequestedFastMCGRecoveryViaSRB3Release(v)
			return &result, nil
		case 379: // id-SNtriggered -> SNtriggered (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SNtriggered (%d): %w", ieId, err)
			}
			result := SNtriggered(v)
			return &result, nil
		case 395: // id-IABNodeIndication -> IABNodeIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IABNodeIndication (%d): %w", ieId, err)
			}
			result := IABNodeIndication(v)
			return &result, nil
		case 416: // id-PSCellHistoryInformationRetrieve -> PSCellHistoryInformationRetrieve (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PSCellHistoryInformationRetrieve (%d): %w", ieId, err)
			}
			result := PSCellHistoryInformationRetrieve(v)
			return &result, nil
		case 105: // id-UE-HistoryInformationFromTheUE -> UE-HistoryInformationFromTheUE (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-HistoryInformationFromTheUE (%d): %w", ieId, err)
			}
			result := UEHistoryInformationFromTheUE(v)
			return &result, nil
		case 421: // id-CHOinformation-ModReq -> CHOinformation-ModReq
			var v CHOinformationModReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CHOinformation-ModReq (%d): %w", ieId, err)
			}
			return &v, nil
		case 423: // id-SCGActivationRequest -> SCGActivationRequest (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGActivationRequest (%d): %w", ieId, err)
			}
			result := SCGActivationRequest(v)
			return &result, nil
		case 426: // id-CPAinformation-MOD -> CPAinformation-MOD
			var v CPAinformationMOD
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPAinformation-MOD (%d): %w", ieId, err)
			}
			return &v, nil
		case 432: // id-CPCupdate-MOD -> CPCupdate-MOD
			var v CPCupdateMOD
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPCupdate-MOD (%d): %w", ieId, err)
			}
			return &v, nil
		case 449: // id-IABAuthorized -> IABAuthorized (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE IABAuthorized (%d): %w", ieId, err)
			}
			result := IABAuthorized(v)
			return &result, nil
		}
	case "ERABsToBeAddedSgNBModReqItem", "E-RABs-ToBeAdded-SgNBModReq-ItemIEs":
		switch ieId {
		case 216: // id-E-RABs-ToBeAdded-SgNBModReq-Item -> ERABsToBeAddedSgNBModReqItem
			var v ERABsToBeAddedSgNBModReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeAddedSgNBModReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsToBeModifiedSgNBModReqItem", "E-RABs-ToBeModified-SgNBModReq-ItemIEs":
		switch ieId {
		case 217: // id-E-RABs-ToBeModified-SgNBModReq-Item -> ERABsToBeModifiedSgNBModReqItem
			var v ERABsToBeModifiedSgNBModReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeModifiedSgNBModReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsToBeReleasedSgNBModReqItem", "E-RABs-ToBeReleased-SgNBModReq-ItemIEs":
		switch ieId {
		case 218: // id-E-RABs-ToBeReleased-SgNBModReq-Item -> ERABsToBeReleasedSgNBModReqItem
			var v ERABsToBeReleasedSgNBModReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBModReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBModificationRequestAcknowledge", "SgNBModificationRequestAcknowledge-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 219: // id-E-RABs-Admitted-ToBeAdded-SgNBModAckList -> ERABsAdmittedToBeAddedSgNBModAckList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeAddedSgNBModAckList (%d): %w", ieId, err)
			}
			return &v, nil
		case 220: // id-E-RABs-Admitted-ToBeModified-SgNBModAckList -> ERABsAdmittedToBeModifiedSgNBModAckList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeModifiedSgNBModAckList (%d): %w", ieId, err)
			}
			return &v, nil
		case 221: // id-E-RABs-Admitted-ToBeReleased-SgNBModAckList -> ERABsAdmittedToBeReleasedSgNBModAckList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeReleasedSgNBModAckList (%d): %w", ieId, err)
			}
			return &v, nil
		case 3: // id-E-RABs-NotAdmitted-List -> E-RAB-List (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RAB-List (%d): %w", ieId, err)
			}
			return &v, nil
		case 211: // id-SgNBtoMeNBContainer -> SgNBtoMeNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBtoMeNBContainer (%d): %w", ieId, err)
			}
			result := SgNBtoMeNBContainer(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 258: // id-SgNBResourceCoordinationInformation -> SgNBResourceCoordinationInformation
			var v SgNBResourceCoordinationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SgNBResourceCoordinationInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 212: // id-AdmittedSplitSRBs -> SplitSRBs (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SplitSRBs (%d): %w", ieId, err)
			}
			result := SplitSRBs(v)
			return &result, nil
		case 281: // id-AdmittedSplitSRBsrelease -> SplitSRBs (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SplitSRBs (%d): %w", ieId, err)
			}
			result := SplitSRBs(v)
			return &result, nil
		case 272: // id-RRCConfigIndication -> RRC-Config-Ind (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RRC-Config-Ind (%d): %w", ieId, err)
			}
			result := RRCConfigInd(v)
			return &result, nil
		case 331: // id-LocationInformationSgNB -> LocationInformationSgNB
			var v LocationInformationSgNB
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LocationInformationSgNB (%d): %w", ieId, err)
			}
			return &v, nil
		case 344: // id-AvailableFastMCGRecoveryViaSRB3 -> AvailableFastMCGRecoveryViaSRB3 (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AvailableFastMCGRecoveryViaSRB3 (%d): %w", ieId, err)
			}
			result := AvailableFastMCGRecoveryViaSRB3(v)
			return &result, nil
		case 346: // id-ReleaseFastMCGRecoveryViaSRB3 -> ReleaseFastMCGRecoveryViaSRB3 (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ReleaseFastMCGRecoveryViaSRB3 (%d): %w", ieId, err)
			}
			result := ReleaseFastMCGRecoveryViaSRB3(v)
			return &result, nil
		case 422: // id-SCGActivationStatus -> SCGActivationStatus (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGActivationStatus (%d): %w", ieId, err)
			}
			result := SCGActivationStatus(v)
			return &result, nil
		case 427: // id-CPAinformation-MOD-ACK -> CPAinformation-MOD-ACK
			var v CPAinformationMODACK
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPAinformation-MOD-ACK (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsAdmittedToBeAddedSgNBModAckItem", "E-RABs-Admitted-ToBeAdded-SgNBModAck-ItemIEs":
		switch ieId {
		case 222: // id-E-RABs-Admitted-ToBeAdded-SgNBModAck-Item -> ERABsAdmittedToBeAddedSgNBModAckItem
			var v ERABsAdmittedToBeAddedSgNBModAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeAddedSgNBModAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsAdmittedToBeModifiedSgNBModAckItem", "E-RABs-Admitted-ToBeModified-SgNBModAck-ItemIEs":
		switch ieId {
		case 223: // id-E-RABs-Admitted-ToBeModified-SgNBModAck-Item -> ERABsAdmittedToBeModifiedSgNBModAckItem
			var v ERABsAdmittedToBeModifiedSgNBModAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeModifiedSgNBModAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsAdmittedToBeReleasedSgNBModAckItem", "E-RABs-Admitted-ToBeReleased-SgNBModAck-ItemIEs":
		switch ieId {
		case 224: // id-E-RABs-Admitted-ToBeReleased-SgNBModAck-Item -> ERABsAdmittedToReleasedSgNBModAckItem
			var v ERABsAdmittedToReleasedSgNBModAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToReleasedSgNBModAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBModificationRequestReject", "SgNBModificationRequestReject-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "SgNBModificationRequired", "SgNBModificationRequired-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 249: // id-PDCPChangeIndication -> PDCPChangeIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PDCPChangeIndication (%d): %w", ieId, err)
			}
			result := PDCPChangeIndication(v)
			return &result, nil
		case 225: // id-E-RABs-ToBeReleased-SgNBModReqdList -> ERABsToBeReleasedSgNBModReqdList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBModReqdList (%d): %w", ieId, err)
			}
			return &v, nil
		case 211: // id-SgNBtoMeNBContainer -> SgNBtoMeNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBtoMeNBContainer (%d): %w", ieId, err)
			}
			result := SgNBtoMeNBContainer(v)
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 226: // id-E-RABs-ToBeModified-SgNBModReqdList -> ERABsToBeModifiedSgNBModReqdList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeModifiedSgNBModReqdList (%d): %w", ieId, err)
			}
			return &v, nil
		case 258: // id-SgNBResourceCoordinationInformation -> SgNBResourceCoordinationInformation
			var v SgNBResourceCoordinationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SgNBResourceCoordinationInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 272: // id-RRCConfigIndication -> RRC-Config-Ind (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RRC-Config-Ind (%d): %w", ieId, err)
			}
			result := RRCConfigInd(v)
			return &result, nil
		case 331: // id-LocationInformationSgNB -> LocationInformationSgNB
			var v LocationInformationSgNB
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LocationInformationSgNB (%d): %w", ieId, err)
			}
			return &v, nil
		case 423: // id-SCGActivationRequest -> SCGActivationRequest (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGActivationRequest (%d): %w", ieId, err)
			}
			result := SCGActivationRequest(v)
			return &result, nil
		case 428: // id-CPACinformation-REQD -> CPACinformation-REQD
			var v CPACinformationREQD
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPACinformation-REQD (%d): %w", ieId, err)
			}
			return &v, nil
		case 438: // id-SCGreconfigNotification -> SCGreconfigNotification (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGreconfigNotification (%d): %w", ieId, err)
			}
			result := SCGreconfigNotification(v)
			return &result, nil
		}
	case "ERABsToBeReleasedSgNBModReqdItem", "E-RABs-ToBeReleased-SgNBModReqd-ItemIEs":
		switch ieId {
		case 227: // id-E-RABs-ToBeReleased-SgNBModReqd-Item -> ERABsToBeReleasedSgNBModReqdItem
			var v ERABsToBeReleasedSgNBModReqdItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBModReqdItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsToBeModifiedSgNBModReqdItem", "E-RABs-ToBeModified-SgNBModReqd-ItemIEs":
		switch ieId {
		case 228: // id-E-RABs-ToBeModified-SgNBModReqd-Item -> ERABsToBeModifiedSgNBModReqdItem
			var v ERABsToBeModifiedSgNBModReqdItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeModifiedSgNBModReqdItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBModificationConfirm", "SgNBModificationConfirm-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 294: // id-E-RABs-AdmittedToBeModified-SgNBModConfList -> ERABsAdmittedToBeModifiedSgNBModConfList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeModifiedSgNBModConfList (%d): %w", ieId, err)
			}
			return &v, nil
		case 206: // id-MeNBtoSgNBContainer -> MeNBtoSgNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeNBtoSgNBContainer (%d): %w", ieId, err)
			}
			result := MeNBtoSgNBContainer(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 257: // id-MeNBResourceCoordinationInformation -> MeNBResourceCoordinationInformation
			var v MeNBResourceCoordinationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE MeNBResourceCoordinationInformation (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsAdmittedToBeModifiedSgNBModConfItem", "E-RABs-AdmittedToBeModified-SgNBModConf-ItemIEs":
		switch ieId {
		case 295: // id-E-RABs-AdmittedToBeModified-SgNBModConf-Item -> ERABsAdmittedToBeModifiedSgNBModConfItem
			var v ERABsAdmittedToBeModifiedSgNBModConfItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeModifiedSgNBModConfItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBModificationRefuse", "SgNBModificationRefuse-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 206: // id-MeNBtoSgNBContainer -> MeNBtoSgNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeNBtoSgNBContainer (%d): %w", ieId, err)
			}
			result := MeNBtoSgNBContainer(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "SgNBReleaseRequest", "SgNBReleaseRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 231: // id-E-RABs-ToBeReleased-SgNBRelReqList -> ERABsToBeReleasedSgNBRelReqList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBRelReqList (%d): %w", ieId, err)
			}
			return &v, nil
		case 154: // id-UE-ContextKeptIndicator -> UE-ContextKeptIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-ContextKeptIndicator (%d): %w", ieId, err)
			}
			result := UEContextKeptIndicator(v)
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 206: // id-MeNBtoSgNBContainer -> MeNBtoSgNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeNBtoSgNBContainer (%d): %w", ieId, err)
			}
			result := MeNBtoSgNBContainer(v)
			return &result, nil
		case 339: // id-ERABs-transferred-to-MeNB -> E-RAB-List (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE E-RAB-List (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsToBeReleasedSgNBRelReqItem", "E-RABs-ToBeReleased-SgNBRelReq-ItemIEs":
		switch ieId {
		case 232: // id-E-RABs-ToBeReleased-SgNBRelReq-Item -> ERABsToBeReleasedSgNBRelReqItem
			var v ERABsToBeReleasedSgNBRelReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBRelReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBReleaseRequestAcknowledge", "SgNBReleaseRequestAcknowledge-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 318: // id-E-RABs-Admitted-ToBeReleased-SgNBRelReqAckList -> ERABsAdmittedToBeReleasedSgNBRelReqAckList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeReleasedSgNBRelReqAckList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsAdmittedToBeReleasedSgNBRelReqAckItem", "E-RABs-Admitted-ToBeReleased-SgNBRelReqAck-ItemIEs":
		switch ieId {
		case 319: // id-E-RABs-Admitted-ToBeReleased-SgNBRelReqAck-Item -> ERABsAdmittedToBeReleasedSgNBRelReqAckItem
			var v ERABsAdmittedToBeReleasedSgNBRelReqAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeReleasedSgNBRelReqAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBReleaseRequestReject", "SgNBReleaseRequestReject-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "SgNBReleaseRequired", "SgNBReleaseRequired-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 320: // id-E-RABs-ToBeReleased-SgNBRelReqdList -> ERABsToBeReleasedSgNBRelReqdList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBRelReqdList (%d): %w", ieId, err)
			}
			return &v, nil
		case 211: // id-SgNBtoMeNBContainer -> SgNBtoMeNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBtoMeNBContainer (%d): %w", ieId, err)
			}
			result := SgNBtoMeNBContainer(v)
			return &result, nil
		}
	case "ERABsToBeReleasedSgNBRelReqdItem", "E-RABs-ToBeReleased-SgNBRelReqd-ItemIEs":
		switch ieId {
		case 321: // id-E-RABs-ToBeReleased-SgNBRelReqd-Item -> ERABsToBeReleasedSgNBRelReqdItem
			var v ERABsToBeReleasedSgNBRelReqdItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBRelReqdItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBReleaseConfirm", "SgNBReleaseConfirm-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 233: // id-E-RABs-ToBeReleased-SgNBRelConfList -> ERABsToBeReleasedSgNBRelConfList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBRelConfList (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "ERABsToBeReleasedSgNBRelConfItem", "E-RABs-ToBeReleased-SgNBRelConf-ItemIEs":
		switch ieId {
		case 234: // id-E-RABs-ToBeReleased-SgNBRelConf-Item -> ERABsToBeReleasedSgNBRelConfItem
			var v ERABsToBeReleasedSgNBRelConfItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBRelConfItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBCounterCheckRequest", "SgNBCounterCheckRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 235: // id-E-RABs-SubjectToSgNBCounterCheck-List -> ERABsSubjectToSgNBCounterCheckList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsSubjectToSgNBCounterCheckList (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "ERABsSubjectToSgNBCounterCheckItem", "E-RABs-SubjectToSgNBCounterCheck-ItemIEs":
		switch ieId {
		case 236: // id-E-RABs-SubjectToSgNBCounterCheck-Item -> ERABsSubjectToSgNBCounterCheckItem
			var v ERABsSubjectToSgNBCounterCheckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsSubjectToSgNBCounterCheckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBChangeRequired", "SgNBChangeRequired-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 239: // id-Target-SgNB-ID -> GlobalGNB-ID
			var v GlobalGNBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalGNB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 211: // id-SgNBtoMeNBContainer -> SgNBtoMeNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBtoMeNBContainer (%d): %w", ieId, err)
			}
			result := SgNBtoMeNBContainer(v)
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 429: // id-CPCinformation-REQD -> CPCinformation-REQD
			var v CPCinformationREQD
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPCinformation-REQD (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "AccessAndMobilityIndication", "AccessAndMobilityIndication-IEs":
		switch ieId {
		case 414: // id-NRRAReport -> NRRAReport (SEQUENCE OF NRRAReportListItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 64)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NRRAReport length: %w", err)
			}
			result := make(NRRAReport, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE NRRAReport item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "SgNBChangeConfirm", "SgNBChangeConfirm-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 229: // id-E-RABs-ToBeReleased-SgNBChaConfList -> ERABsToBeReleasedSgNBChaConfList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBChaConfList (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 430: // id-CPCinformation-CONF -> CPCinformation-CONF
			var v CPCinformationCONF
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPCinformation-CONF (%d): %w", ieId, err)
			}
			return &v, nil
		case 206: // id-MeNBtoSgNBContainer -> MeNBtoSgNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeNBtoSgNBContainer (%d): %w", ieId, err)
			}
			result := MeNBtoSgNBContainer(v)
			return &result, nil
		}
	case "ERABsToBeReleasedSgNBChaConfItem", "E-RABs-ToBeReleased-SgNBChaConf-ItemIEs":
		switch ieId {
		case 230: // id-E-RABs-ToBeReleased-SgNBChaConf-Item -> ERABsToBeReleasedSgNBChaConfItem
			var v ERABsToBeReleasedSgNBChaConfItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBChaConfItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "RRCTransfer", "RRCTransfer-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 242: // id-SplitSRB -> SplitSRB
			var v SplitSRB
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SplitSRB (%d): %w", ieId, err)
			}
			return &v, nil
		case 243: // id-NRUeReport -> NRUeReport
			var v NRUeReport
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRUeReport (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 342: // id-FastMCGRecovery-SN-to-MN -> FastMCGRecovery
			var v FastMCGRecovery
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE FastMCGRecovery (%d): %w", ieId, err)
			}
			return &v, nil
		case 347: // id-FastMCGRecovery-MN-to-SN -> FastMCGRecovery
			var v FastMCGRecovery
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE FastMCGRecovery (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBChangeRefuse", "SgNBChangeRefuse-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "ENDCX2SetupRequest", "ENDCX2SetupRequest-IEs":
		switch ieId {
		case 244: // id-InitiatingNodeType-EndcX2Setup -> InitiatingNodeTypeEndcX2Setup
			var v InitiatingNodeTypeEndcX2Setup
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE InitiatingNodeTypeEndcX2Setup (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		case 352: // id-TNLConfigurationInfo -> TNLConfigurationInfo
			var v TNLConfigurationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TNLConfigurationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENBENDCX2SetupReq", "ENB-ENDCX2SetupReqIEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENB-ID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		case 250: // id-ServedEUTRAcellsENDCX2ManagementList -> ServedEUTRAcellsENDCX2ManagementList (SEQUENCE OF ServedEUTRAcellsENDCX2ManagementListElem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedEUTRAcellsENDCX2ManagementList length: %w", err)
			}
			result := make(ServedEUTRAcellsENDCX2ManagementList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedEUTRAcellsENDCX2ManagementList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		case 351: // id-CellandCapacityAssistInfo -> CellandCapacityAssistInfo
			var v CellandCapacityAssistInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellandCapacityAssistInfo (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "EnGNBENDCX2SetupReq", "En-gNB-ENDCX2SetupReqIEs":
		switch ieId {
		case 252: // id-Globalen-gNB-ID -> GlobalGNB-ID
			var v GlobalGNBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalGNB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		case 253: // id-ServedNRcellsENDCX2ManagementList -> ServedNRcellsENDCX2ManagementList (SEQUENCE OF ServedNRcellsENDCX2ManagementListElem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16384)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedNRcellsENDCX2ManagementList length: %w", err)
			}
			result := make(ServedNRcellsENDCX2ManagementList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedNRcellsENDCX2ManagementList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 348: // id-PartialListIndicator -> PartialListIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PartialListIndicator (%d): %w", ieId, err)
			}
			result := PartialListIndicator(v)
			return &result, nil
		}
	case "ENDCX2SetupResponse", "ENDCX2SetupResponse-IEs":
		switch ieId {
		case 246: // id-RespondingNodeType-EndcX2Setup -> RespondingNodeTypeEndcX2Setup
			var v RespondingNodeTypeEndcX2Setup
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RespondingNodeTypeEndcX2Setup (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		case 352: // id-TNLConfigurationInfo -> TNLConfigurationInfo
			var v TNLConfigurationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TNLConfigurationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENBENDCX2SetupReqAck", "ENB-ENDCX2SetupReqAckIEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENB-ID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		case 250: // id-ServedEUTRAcellsENDCX2ManagementList -> ServedEUTRAcellsENDCX2ManagementList (SEQUENCE OF ServedEUTRAcellsENDCX2ManagementListElem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedEUTRAcellsENDCX2ManagementList length: %w", err)
			}
			result := make(ServedEUTRAcellsENDCX2ManagementList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedEUTRAcellsENDCX2ManagementList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		case 351: // id-CellandCapacityAssistInfo -> CellandCapacityAssistInfo
			var v CellandCapacityAssistInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellandCapacityAssistInfo (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "EnGNBENDCX2SetupReqAck", "En-gNB-ENDCX2SetupReqAckIEs":
		switch ieId {
		case 252: // id-Globalen-gNB-ID -> GlobalGNB-ID
			var v GlobalGNBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalGNB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		case 253: // id-ServedNRcellsENDCX2ManagementList -> ServedNRcellsENDCX2ManagementList (SEQUENCE OF ServedNRcellsENDCX2ManagementListElem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16384)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedNRcellsENDCX2ManagementList length: %w", err)
			}
			result := make(ServedNRcellsENDCX2ManagementList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedNRcellsENDCX2ManagementList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 348: // id-PartialListIndicator -> PartialListIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PartialListIndicator (%d): %w", ieId, err)
			}
			result := PartialListIndicator(v)
			return &result, nil
		}
	case "ENDCX2SetupFailure", "ENDCX2SetupFailure-IEs":
		switch ieId {
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 22: // id-TimeToWait -> TimeToWait (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 6, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeToWait (%d): %w", ieId, err)
			}
			result := TimeToWait(v)
			return &result, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		case 350: // id-MessageOversizeNotification -> MessageOversizeNotification
			var v MessageOversizeNotification
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE MessageOversizeNotification (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENDCConfigurationUpdate", "ENDCConfigurationUpdate-IEs":
		switch ieId {
		case 245: // id-InitiatingNodeType-EndcConfigUpdate -> InitiatingNodeTypeEndcConfigUpdate
			var v InitiatingNodeTypeEndcConfigUpdate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE InitiatingNodeTypeEndcConfigUpdate (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		case 352: // id-TNLConfigurationInfo -> TNLConfigurationInfo
			var v TNLConfigurationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TNLConfigurationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 353: // id-TNLA-To-Add-List -> TNLA-To-Add-List (SEQUENCE OF TNLAToAddItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 32)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TNLA-To-Add-List length: %w", err)
			}
			result := make(TNLAToAddList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE TNLA-To-Add-List item %d: %w", i, err)
				}
			}
			return &result, nil
		case 354: // id-TNLA-To-Update-List -> TNLA-To-Update-List (SEQUENCE OF TNLAToUpdateItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 32)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TNLA-To-Update-List length: %w", err)
			}
			result := make(TNLAToUpdateList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE TNLA-To-Update-List item %d: %w", i, err)
				}
			}
			return &result, nil
		case 355: // id-TNLA-To-Remove-List -> TNLA-To-Remove-List (SEQUENCE OF TNLAToRemoveItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 32)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TNLA-To-Remove-List length: %w", err)
			}
			result := make(TNLAToRemoveList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE TNLA-To-Remove-List item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "ENBENDCConfigUpdate", "ENB-ENDCConfigUpdateIEs":
		switch ieId {
		case 251: // id-CellAssistanceInformation -> CellAssistanceInformation
			var v CellAssistanceInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellAssistanceInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 250: // id-ServedEUTRAcellsENDCX2ManagementList -> ServedEUTRAcellsENDCX2ManagementList (SEQUENCE OF ServedEUTRAcellsENDCX2ManagementListElem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedEUTRAcellsENDCX2ManagementList length: %w", err)
			}
			result := make(ServedEUTRAcellsENDCX2ManagementList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedEUTRAcellsENDCX2ManagementList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 259: // id-ServedEUTRAcellsToModifyListENDCConfUpd -> ServedEUTRAcellsToModifyListENDCConfUpd (SEQUENCE OF ServedEUTRAcellsToModifyListENDCConfUpdElem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedEUTRAcellsToModifyListENDCConfUpd length: %w", err)
			}
			result := make(ServedEUTRAcellsToModifyListENDCConfUpd, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedEUTRAcellsToModifyListENDCConfUpd item %d: %w", i, err)
				}
			}
			return &result, nil
		case 260: // id-ServedEUTRAcellsToDeleteListENDCConfUpd -> ServedEUTRAcellsToDeleteListENDCConfUpd (SEQUENCE OF ECGI)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedEUTRAcellsToDeleteListENDCConfUpd length: %w", err)
			}
			result := make(ServedEUTRAcellsToDeleteListENDCConfUpd, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedEUTRAcellsToDeleteListENDCConfUpd item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "EnGNBENDCConfigUpdate", "En-gNB-ENDCConfigUpdateIEs":
		switch ieId {
		case 253: // id-ServedNRcellsENDCX2ManagementList -> ServedNRcellsENDCX2ManagementList (SEQUENCE OF ServedNRcellsENDCX2ManagementListElem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16384)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedNRcellsENDCX2ManagementList length: %w", err)
			}
			result := make(ServedNRcellsENDCX2ManagementList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedNRcellsENDCX2ManagementList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 261: // id-ServedNRcellsToModifyListENDCConfUpd -> ServedNRcellsToModifyENDCConfUpdList (SEQUENCE OF ServedNRCellsToModifyItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16384)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedNRcellsToModifyENDCConfUpdList length: %w", err)
			}
			result := make(ServedNRcellsToModifyENDCConfUpdList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedNRcellsToModifyENDCConfUpdList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 262: // id-ServedNRcellsToDeleteListENDCConfUpd -> ServedNRcellsToDeleteENDCConfUpdList (SEQUENCE OF NRCGI)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16384)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedNRcellsToDeleteENDCConfUpdList length: %w", err)
			}
			result := make(ServedNRcellsToDeleteENDCConfUpdList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedNRcellsToDeleteENDCConfUpdList item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "ENDCConfigurationUpdateAcknowledge", "ENDCConfigurationUpdateAcknowledge-IEs":
		switch ieId {
		case 247: // id-RespondingNodeType-EndcConfigUpdate -> RespondingNodeTypeEndcConfigUpdate
			var v RespondingNodeTypeEndcConfigUpdate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RespondingNodeTypeEndcConfigUpdate (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 352: // id-TNLConfigurationInfo -> TNLConfigurationInfo
			var v TNLConfigurationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TNLConfigurationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 356: // id-TNLA-Setup-List -> TNLA-Setup-List (SEQUENCE OF TNLASetupItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 32)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TNLA-Setup-List length: %w", err)
			}
			result := make(TNLASetupList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE TNLA-Setup-List item %d: %w", i, err)
				}
			}
			return &result, nil
		case 357: // id-TNLA-Failed-To-Setup-List -> TNLA-Failed-To-Setup-List (SEQUENCE OF TNLAFailedToSetupItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 32)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TNLA-Failed-To-Setup-List length: %w", err)
			}
			result := make(TNLAFailedToSetupList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE TNLA-Failed-To-Setup-List item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "EnGNBENDCConfigUpdateAck", "En-gNB-ENDCConfigUpdateAckIEs":
		switch ieId {
		case 253: // id-ServedNRcellsENDCX2ManagementList -> ServedNRcellsENDCX2ManagementList (SEQUENCE OF ServedNRcellsENDCX2ManagementListElem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16384)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedNRcellsENDCX2ManagementList length: %w", err)
			}
			result := make(ServedNRcellsENDCX2ManagementList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedNRcellsENDCX2ManagementList item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "ENDCConfigurationUpdateFailure", "ENDCConfigurationUpdateFailure-IEs":
		switch ieId {
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 22: // id-TimeToWait -> TimeToWait (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 6, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeToWait (%d): %w", ieId, err)
			}
			result := TimeToWait(v)
			return &result, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "ENDCCellActivationRequest", "ENDCCellActivationRequest-IEs":
		switch ieId {
		case 267: // id-ServedNRCellsToActivate -> ServedNRCellsToActivate (SEQUENCE OF ServedNRCellsToActivateItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16384)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedNRCellsToActivate length: %w", err)
			}
			result := make(ServedNRCellsToActivate, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ServedNRCellsToActivate item %d: %w", i, err)
				}
			}
			return &result, nil
		case 256: // id-ActivationID -> ActivationID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ActivationID (%d): %w", ieId, err)
			}
			result := ActivationID(v)
			return &result, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "ENDCCellActivationResponse", "ENDCCellActivationResponse-IEs":
		switch ieId {
		case 268: // id-ActivatedNRCellList -> ActivatedNRCellList (SEQUENCE OF ActivatedNRCellListItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16384)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ActivatedNRCellList length: %w", err)
			}
			result := make(ActivatedNRCellList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ActivatedNRCellList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 256: // id-ActivationID -> ActivationID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ActivationID (%d): %w", ieId, err)
			}
			result := ActivationID(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "ENDCCellActivationFailure", "ENDCCellActivationFailure-IEs":
		switch ieId {
		case 256: // id-ActivationID -> ActivationID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ActivationID (%d): %w", ieId, err)
			}
			result := ActivationID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "ENDCResourceStatusRequest", "ENDCResourceStatusRequest-IEs":
		switch ieId {
		case 383: // id-E-UTRAN-Node1-Measurement-ID -> Measurement-ID-ENDC (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID-ENDC (%d): %w", ieId, err)
			}
			result := MeasurementIDENDC(v)
			return &result, nil
		case 384: // id-E-UTRAN-Node2-Measurement-ID -> Measurement-ID-ENDC (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID-ENDC (%d): %w", ieId, err)
			}
			result := MeasurementIDENDC(v)
			return &result, nil
		case 28: // id-Registration-Request -> Registration-Request-ENDC (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Registration-Request-ENDC (%d): %w", ieId, err)
			}
			result := RegistrationRequestENDC(v)
			return &result, nil
		case 30: // id-ReportingPeriodicity -> ReportingPeriodicityENDC (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 5, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ReportingPeriodicityENDC (%d): %w", ieId, err)
			}
			result := ReportingPeriodicityENDC(v)
			return &result, nil
		case 38: // id-ReportCharacteristics -> ReportCharacteristics-ENDC (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ReportCharacteristics-ENDC (%d): %w", ieId, err)
			}
			result := ReportCharacteristicsENDC{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 391: // id-CellToReport-NR-ENDC -> CellToReportNRENDCList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 16384)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellToReportNRENDCList (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		case 403: // id-CellToReport-E-UTRA-ENDC -> CellToReportEUTRAENDCList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellToReportEUTRAENDCList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CellToReportNRENDCItem", "CellToReport-NR-ENDC-ItemIEs":
		switch ieId {
		case 392: // id-CellToReport-NR-ENDC-Item -> CellToReportNRENDCItem
			var v CellToReportNRENDCItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellToReportNRENDCItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CellToReportEUTRAENDCItem", "CellToReport-E-UTRA-ENDC-Item-IEs":
		switch ieId {
		case 404: // id-CellToReport-E-UTRA-ENDC-Item -> CellToReportEUTRAENDCItem
			var v CellToReportEUTRAENDCItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellToReportEUTRAENDCItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENDCResourceStatusResponse", "ENDCResourceStatusResponse-IEs":
		switch ieId {
		case 383: // id-E-UTRAN-Node1-Measurement-ID -> Measurement-ID-ENDC (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID-ENDC (%d): %w", ieId, err)
			}
			result := MeasurementIDENDC(v)
			return &result, nil
		case 384: // id-E-UTRAN-Node2-Measurement-ID -> Measurement-ID-ENDC (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID-ENDC (%d): %w", ieId, err)
			}
			result := MeasurementIDENDC(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "ENDCResourceStatusFailure", "ENDCResourceStatusFailure-IEs":
		switch ieId {
		case 383: // id-E-UTRAN-Node1-Measurement-ID -> Measurement-ID-ENDC (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID-ENDC (%d): %w", ieId, err)
			}
			result := MeasurementIDENDC(v)
			return &result, nil
		case 384: // id-E-UTRAN-Node2-Measurement-ID -> Measurement-ID-ENDC (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID-ENDC (%d): %w", ieId, err)
			}
			result := MeasurementIDENDC(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "ENDCResourceStatusUpdate", "ENDCResourceStatusUpdate-IEs":
		switch ieId {
		case 383: // id-E-UTRAN-Node1-Measurement-ID -> Measurement-ID-ENDC (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID-ENDC (%d): %w", ieId, err)
			}
			result := MeasurementIDENDC(v)
			return &result, nil
		case 384: // id-E-UTRAN-Node2-Measurement-ID -> Measurement-ID-ENDC (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Measurement-ID-ENDC (%d): %w", ieId, err)
			}
			result := MeasurementIDENDC(v)
			return &result, nil
		case 393: // id-CellMeasurementResult-NR-ENDC -> CellMeasurementResultNRENDCList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 16384)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellMeasurementResultNRENDCList (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		case 401: // id-CellMeasurementResult-E-UTRA-ENDC -> CellMeasurementResultEUTRAENDCList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellMeasurementResultEUTRAENDCList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CellMeasurementResultNRENDCItem", "CellMeasurementResult-NR-ENDC-ItemIEs":
		switch ieId {
		case 394: // id-CellMeasurementResult-NR-ENDC-Item -> CellMeasurementResultNRENDCItem
			var v CellMeasurementResultNRENDCItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellMeasurementResultNRENDCItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CellMeasurementResultEUTRAENDCItem", "CellMeasurementResult-E-UTRA-ENDC-ItemIEs":
		switch ieId {
		case 402: // id-CellMeasurementResult-E-UTRA-ENDC-Item -> CellMeasurementResultEUTRAENDCItem
			var v CellMeasurementResultEUTRAENDCItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellMeasurementResultEUTRAENDCItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SecondaryRATDataUsageReport", "SecondaryRATDataUsageReport-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 265: // id-SecondaryRATUsageReportList -> SecondaryRATUsageReportList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SecondaryRATUsageReportList (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "SgNBActivityNotification", "SgNBActivityNotification-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 296: // id-UEContextLevelUserPlaneActivity -> UserPlaneTrafficActivityReport (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UserPlaneTrafficActivityReport (%d): %w", ieId, err)
			}
			result := UserPlaneTrafficActivityReport(v)
			return &result, nil
		case 297: // id-ERABActivityNotifyItemList -> ERABActivityNotifyItemList (SEQUENCE OF ERABActivityNotifyItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABActivityNotifyItemList length: %w", err)
			}
			result := make(ERABActivityNotifyItemList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ERABActivityNotifyItemList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "ENDCPartialResetRequired", "ENDCPartialResetRequired-IEs":
		switch ieId {
		case 270: // id-UEs-ToBeReset -> UEsToBeResetList (SEQUENCE OF UEsToBeResetListItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 8192)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEsToBeResetList length: %w", err)
			}
			result := make(UEsToBeResetList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE UEsToBeResetList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "ENDCPartialResetConfirm", "ENDCPartialResetConfirm-IEs":
		switch ieId {
		case 271: // id-UEs-Admitted-ToBeReset -> UEsToBeResetList (SEQUENCE OF UEsToBeResetListItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 8192)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEsToBeResetList length: %w", err)
			}
			result := make(UEsToBeResetList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE UEsToBeResetList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "EUTRANRCellResourceCoordinationRequest", "EUTRANRCellResourceCoordinationRequest-IEs":
		switch ieId {
		case 285: // id-InitiatingNodeType-EutranrCellResourceCoordination -> InitiatingNodeTypeEutranrCellResourceCoordination
			var v InitiatingNodeTypeEutranrCellResourceCoordination
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE InitiatingNodeTypeEutranrCellResourceCoordination (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "ENBEUTRANRCellResourceCoordinationReq", "ENB-EUTRA-NRCellResourceCoordinationReqIEs":
		switch ieId {
		case 287: // id-DataTrafficResourceIndication -> DataTrafficResourceIndication
			var v DataTrafficResourceIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE DataTrafficResourceIndication (%d): %w", ieId, err)
			}
			return &v, nil
		case 288: // id-SpectrumSharingGroupID -> SpectrumSharingGroupID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(256), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SpectrumSharingGroupID (%d): %w", ieId, err)
			}
			result := SpectrumSharingGroupID(v)
			return &result, nil
		case 289: // id-ListofEUTRACellsinEUTRACoordinationReq -> ListofEUTRACellsinEUTRACoordinationReq (SEQUENCE OF ECGI)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ListofEUTRACellsinEUTRACoordinationReq length: %w", err)
			}
			result := make(ListofEUTRACellsinEUTRACoordinationReq, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ListofEUTRACellsinEUTRACoordinationReq item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "EnGNBEUTRANRCellResourceCoordinationReq", "En-gNB-EUTRA-NRCellResourceCoordinationReqIEs":
		switch ieId {
		case 287: // id-DataTrafficResourceIndication -> DataTrafficResourceIndication
			var v DataTrafficResourceIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE DataTrafficResourceIndication (%d): %w", ieId, err)
			}
			return &v, nil
		case 291: // id-ListofEUTRACellsinNRCoordinationReq -> ListofEUTRACellsinNRCoordinationReq (SEQUENCE OF ECGI)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ListofEUTRACellsinNRCoordinationReq length: %w", err)
			}
			result := make(ListofEUTRACellsinNRCoordinationReq, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ListofEUTRACellsinNRCoordinationReq item %d: %w", i, err)
				}
			}
			return &result, nil
		case 288: // id-SpectrumSharingGroupID -> SpectrumSharingGroupID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(256), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SpectrumSharingGroupID (%d): %w", ieId, err)
			}
			result := SpectrumSharingGroupID(v)
			return &result, nil
		case 292: // id-ListofNRCellsinNRCoordinationReq -> ListofNRCellsinNRCoordinationReq (SEQUENCE OF NRCGI)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 64)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ListofNRCellsinNRCoordinationReq length: %w", err)
			}
			result := make(ListofNRCellsinNRCoordinationReq, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ListofNRCellsinNRCoordinationReq item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "EUTRANRCellResourceCoordinationResponse", "EUTRANRCellResourceCoordinationResponse-IEs":
		switch ieId {
		case 286: // id-RespondingNodeType-EutranrCellResourceCoordination -> RespondingNodeTypeEutranrCellResourceCoordination
			var v RespondingNodeTypeEutranrCellResourceCoordination
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RespondingNodeTypeEutranrCellResourceCoordination (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "ENBEUTRANRCellResourceCoordinationReqAck", "ENB-EUTRA-NRCellResourceCoordinationReqAckIEs":
		switch ieId {
		case 287: // id-DataTrafficResourceIndication -> DataTrafficResourceIndication
			var v DataTrafficResourceIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE DataTrafficResourceIndication (%d): %w", ieId, err)
			}
			return &v, nil
		case 288: // id-SpectrumSharingGroupID -> SpectrumSharingGroupID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(256), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SpectrumSharingGroupID (%d): %w", ieId, err)
			}
			result := SpectrumSharingGroupID(v)
			return &result, nil
		case 290: // id-ListofEUTRACellsinEUTRACoordinationResp -> ListofEUTRACellsinEUTRACoordinationResp (SEQUENCE OF ECGI)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ListofEUTRACellsinEUTRACoordinationResp length: %w", err)
			}
			result := make(ListofEUTRACellsinEUTRACoordinationResp, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ListofEUTRACellsinEUTRACoordinationResp item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "EnGNBEUTRANRCellResourceCoordinationReqAck", "En-gNB-EUTRA-NRCellResourceCoordinationReqAckIEs":
		switch ieId {
		case 287: // id-DataTrafficResourceIndication -> DataTrafficResourceIndication
			var v DataTrafficResourceIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE DataTrafficResourceIndication (%d): %w", ieId, err)
			}
			return &v, nil
		case 288: // id-SpectrumSharingGroupID -> SpectrumSharingGroupID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(256), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SpectrumSharingGroupID (%d): %w", ieId, err)
			}
			result := SpectrumSharingGroupID(v)
			return &result, nil
		case 293: // id-ListofNRCellsinNRCoordinationResp -> ListofNRCellsinNRCoordinationResp (SEQUENCE OF NRCGI)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 0, 64)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ListofNRCellsinNRCoordinationResp length: %w", err)
			}
			result := make(ListofNRCellsinNRCoordinationResp, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE ListofNRCellsinNRCoordinationResp item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "ENDCX2RemovalRequest", "ENDCX2RemovalRequest-IEs":
		switch ieId {
		case 298: // id-InitiatingNodeType-EndcX2Removal -> InitiatingNodeTypeEndcX2Removal
			var v InitiatingNodeTypeEndcX2Removal
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE InitiatingNodeTypeEndcX2Removal (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "ENBENDCX2RemovalReq", "ENB-ENDCX2RemovalReqIEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENB-ID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "EnGNBENDCX2RemovalReq", "En-gNB-ENDCX2RemovalReqIEs":
		switch ieId {
		case 252: // id-Globalen-gNB-ID -> GlobalGNB-ID
			var v GlobalGNBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalGNB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENDCX2RemovalResponse", "ENDCX2RemovalResponse-IEs":
		switch ieId {
		case 299: // id-RespondingNodeType-EndcX2Removal -> RespondingNodeTypeEndcX2Removal
			var v RespondingNodeTypeEndcX2Removal
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RespondingNodeTypeEndcX2Removal (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "ENBENDCX2RemovalReqAck", "ENB-ENDCX2RemovalReqAckIEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENB-ID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "EnGNBENDCX2RemovalReqAck", "En-gNB-ENDCX2RemovalReqAckIEs":
		switch ieId {
		case 252: // id-Globalen-gNB-ID -> GlobalGNB-ID
			var v GlobalGNBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalGNB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENDCX2RemovalFailure", "ENDCX2RemovalFailure-IEs":
		switch ieId {
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "DataForwardingAddressIndication", "DataForwardingAddressIndication-IEs":
		switch ieId {
		case 9: // id-New-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 10: // id-Old-eNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 307: // id-E-RABs-DataForwardingAddress-List -> ERABsDataForwardingAddressList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsDataForwardingAddressList (%d): %w", ieId, err)
			}
			return &v, nil
		case 368: // id-CHO-DC-Indicator -> CHO-DC-Indicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CHO-DC-Indicator (%d): %w", ieId, err)
			}
			result := CHODCIndicator(v)
			return &result, nil
		case 407: // id-CHO-DC-EarlyDataForwarding -> CHO-DC-EarlyDataForwarding (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CHO-DC-EarlyDataForwarding (%d): %w", ieId, err)
			}
			result := CHODCEarlyDataForwarding(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 431: // id-CPCinformation-NOTIFY -> CPCinformation-NOTIFY
			var v CPCinformationNOTIFY
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPCinformation-NOTIFY (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ERABsDataForwardingAddressItem", "E-RABs-DataForwardingAddress-ItemIEs":
		switch ieId {
		case 308: // id-E-RABs-DataForwardingAddress-Item -> ERABsDataForwardingAddressItem
			var v ERABsDataForwardingAddressItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsDataForwardingAddressItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "GNBStatusIndication", "GNBStatusIndicationIEs":
		switch ieId {
		case 310: // id-GNBOverloadInformation -> GNBOverloadInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GNBOverloadInformation (%d): %w", ieId, err)
			}
			result := GNBOverloadInformation(v)
			return &result, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "ENDCConfigurationTransfer", "ENDCConfigurationTransfer-IEs":
		switch ieId {
		case 326: // id-endcSONConfigurationTransfer -> EndcSONConfigurationTransfer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EndcSONConfigurationTransfer (%d): %w", ieId, err)
			}
			result := EndcSONConfigurationTransfer(v)
			return &result, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			result := InterfaceInstanceIndication(v)
			return &result, nil
		}
	case "TraceStart", "TraceStartIEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 13: // id-TraceActivation -> TraceActivation
			var v TraceActivation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TraceActivation (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "DeactivateTrace", "DeactivateTraceIEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 333: // id-EUTRANTraceID -> EUTRANTraceID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EUTRANTraceID (%d): %w", ieId, err)
			}
			result := EUTRANTraceID(v)
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "CellTrafficTrace", "CellTrafficTraceIEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 333: // id-EUTRANTraceID -> EUTRANTraceID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EUTRANTraceID (%d): %w", ieId, err)
			}
			result := EUTRANTraceID(v)
			return &result, nil
		case 377: // id-TraceCollectionEntityIPAddress -> TraceCollectionEntityIPAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TraceCollectionEntityIPAddress (%d): %w", ieId, err)
			}
			result := TraceCollectionEntityIPAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 376: // id-PrivacyIndicator -> PrivacyIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PrivacyIndicator (%d): %w", ieId, err)
			}
			result := PrivacyIndicator(v)
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "F1CTrafficTransfer", "F1CTrafficTransfer-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 397: // id-F1CTrafficContainer -> F1CTrafficContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE F1CTrafficContainer (%d): %w", ieId, err)
			}
			result := F1CTrafficContainer(v)
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		}
	case "UERadioCapabilityIDMappingRequest", "UERadioCapabilityIDMappingRequestIEs":
		switch ieId {
		case 378: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityID (%d): %w", ieId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		}
	case "UERadioCapabilityIDMappingResponse", "UERadioCapabilityIDMappingResponseIEs":
		switch ieId {
		case 378: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityID (%d): %w", ieId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		case 400: // id-UERadioCapability -> UERadioCapability (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapability (%d): %w", ieId, err)
			}
			result := UERadioCapability(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CPCCancel", "CPC-cancel-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UE-X2AP-ID-Extension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID-Extension (%d): %w", ieId, err)
			}
			result := UEX2APIDExtension(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 239: // id-Target-SgNB-ID -> GlobalGNB-ID
			var v GlobalGNBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalGNB-ID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "RachIndication", "RachIndication-IEs":
		switch ieId {
		case 447: // id-RaReportIndicationList -> RaReportIndicationList (SEQUENCE OF RaReportIndicationListItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 64)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RaReportIndicationList length: %w", err)
			}
			result := make(RaReportIndicationList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding IE RaReportIndicationList item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "SCGFailureInformationReport", "SCGFailureInformationReport-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 450: // id-SourcePSCellCGI -> NRCGI
			var v NRCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRCGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 451: // id-FailedPSCellCGI -> NRCGI
			var v NRCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE NRCGI (%d): %w", ieId, err)
			}
			return &v, nil
		case 452: // id-SCG-FailureReportContainer -> SCG-FailureReportContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCG-FailureReportContainer (%d): %w", ieId, err)
			}
			result := SCGFailureReportContainer(v)
			return &result, nil
		case 453: // id-TimeSCG-Failure -> TimeSCG-Failure (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(1023), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeSCG-Failure (%d): %w", ieId, err)
			}
			result := TimeSCGFailure(v)
			return &result, nil
		}
	case "SCGFailureTransfer", "SCGFailureTransfer-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNB-UE-X2AP-ID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNB-UE-X2AP-ID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		}
	}
	return nil, nil
}

// DecodeExtensionFieldValue decodes a known extension open value using its object-set context and ID.
// Returns the decoded typed value, or nil if the combination is unknown.
func DecodeExtensionFieldValue(context string, extensionId int64, data []byte) (interface{}, error) {
	bb := per.NewBitBufferFromBytes(data)
	switch context {
	case "CHOinformationREQExtIEs", "CHOinformation-REQ-ExtIEs":
		switch extensionId {
		case 446: // id-CHOTimeBasedInformation -> CHOTimeBasedInformation
			var v CHOTimeBasedInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension CHOTimeBasedInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ERABLevelQoSParametersExtIEs", "E-RAB-Level-QoS-Parameters-ExtIEs":
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
	case "FDDInfoExtIEs", "FDD-Info-ExtIEs":
		switch extensionId {
		case 95: // id-UL-EARFCNExtension -> EARFCNExtension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(65536), int64Ptr(262143), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EARFCNExtension (%d): %w", extensionId, err)
			}
			result := EARFCNExtension(v)
			return &result, nil
		case 96: // id-DL-EARFCNExtension -> EARFCNExtension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(65536), int64Ptr(262143), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EARFCNExtension (%d): %w", extensionId, err)
			}
			result := EARFCNExtension(v)
			return &result, nil
		case 177: // id-OffsetOfNbiotChannelNumberToDL-EARFCN -> OffsetOfNbiotChannelNumberToEARFCN (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 21, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension OffsetOfNbiotChannelNumberToEARFCN (%d): %w", extensionId, err)
			}
			result := OffsetOfNbiotChannelNumberToEARFCN(v)
			return &result, nil
		case 178: // id-OffsetOfNbiotChannelNumberToUL-EARFCN -> OffsetOfNbiotChannelNumberToEARFCN (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 21, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension OffsetOfNbiotChannelNumberToEARFCN (%d): %w", extensionId, err)
			}
			result := OffsetOfNbiotChannelNumberToEARFCN(v)
			return &result, nil
		case 282: // id-NRS-NSSS-PowerOffset -> NRS-NSSS-PowerOffset (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRS-NSSS-PowerOffset (%d): %w", extensionId, err)
			}
			result := NRSNSSSPowerOffset(v)
			return &result, nil
		case 283: // id-NSSS-NumOccasionDifferentPrecoder -> NSSS-NumOccasionDifferentPrecoder (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NSSS-NumOccasionDifferentPrecoder (%d): %w", extensionId, err)
			}
			result := NSSSNumOccasionDifferentPrecoder(v)
			return &result, nil
		}
	case "FDDInfoNeighbourServedNRCellInformationExtIEs", "FDD-InfoNeighbourServedNRCell-Information-ExtIEs":
		switch extensionId {
		case 387: // id-ULCarrierList -> NRCarrierList (SEQUENCE OF NRCarrierItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 5)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCarrierList length: %w", err)
			}
			result := make(NRCarrierList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension NRCarrierList item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "GBRQosInformationExtIEs", "GBR-QosInformation-ExtIEs":
		switch extensionId {
		case 196: // id-extended-e-RAB-MaximumBitrateDL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(10000000001), int64Ptr(4000000000000), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			result := ExtendedBitRate(v)
			return &result, nil
		case 197: // id-extended-e-RAB-MaximumBitrateUL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(10000000001), int64Ptr(4000000000000), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			result := ExtendedBitRate(v)
			return &result, nil
		case 198: // id-extended-e-RAB-GuaranteedBitrateDL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(10000000001), int64Ptr(4000000000000), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			result := ExtendedBitRate(v)
			return &result, nil
		case 199: // id-extended-e-RAB-GuaranteedBitrateUL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(10000000001), int64Ptr(4000000000000), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			result := ExtendedBitRate(v)
			return &result, nil
		}
	case "GTPtunnelEndpointExtIEs", "GTPtunnelEndpoint-ExtIEs":
		switch extensionId {
		case 396: // id-QoS-Mapping-Information -> QoS-Mapping-Information
			var v QoSMappingInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension QoS-Mapping-Information (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "HandoverRestrictionListExtIEs", "HandoverRestrictionList-ExtIEs":
		switch extensionId {
		case 202: // id-NRrestrictioninEPSasSecondaryRAT -> NRrestrictioninEPSasSecondaryRAT (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRrestrictioninEPSasSecondaryRAT (%d): %w", extensionId, err)
			}
			result := NRrestrictioninEPSasSecondaryRAT(v)
			return &result, nil
		case 301: // id-CNTypeRestrictions -> CNTypeRestrictions (SEQUENCE OF CNTypeRestrictionsItem)
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
		case 305: // id-NRrestrictionin5GS -> NRrestrictionin5GS (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRrestrictionin5GS (%d): %w", extensionId, err)
			}
			result := NRrestrictionin5GS(v)
			return &result, nil
		case 332: // id-LastNG-RANPLMNIdentity -> PLMN-Identity (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PLMN-Identity (%d): %w", extensionId, err)
			}
			result := PLMNIdentity(v)
			return &result, nil
		case 358: // id-UnlicensedSpectrumRestriction -> UnlicensedSpectrumRestriction (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension UnlicensedSpectrumRestriction (%d): %w", extensionId, err)
			}
			result := UnlicensedSpectrumRestriction(v)
			return &result, nil
		case 437: // id-RAT-Restrictions -> RAT-Restrictions (SEQUENCE OF RATRestrictionsItem)
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
	case "LastVisitedEUTRANCellInformationExtIEs", "LastVisitedEUTRANCellInformation-ExtIEs":
		switch extensionId {
		case 77: // id-Time-UE-StayedInCell-EnhancedGranularity -> Time-UE-StayedInCell-EnhancedGranularity (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(40950), false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Time-UE-StayedInCell-EnhancedGranularity (%d): %w", extensionId, err)
			}
			result := TimeUEStayedInCellEnhancedGranularity(v)
			return &result, nil
		case 80: // id-HO-cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension Cause (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "LocationReportingInformationExtIEs", "LocationReportingInformation-ExtIEs":
		switch extensionId {
		case 409: // id-AdditionLocationInformation -> AdditionLocationInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension AdditionLocationInformation (%d): %w", extensionId, err)
			}
			result := AdditionLocationInformation(v)
			return &result, nil
		}
	case "M4ConfigurationExtIEs", "M4Configuration-ExtIEs":
		switch extensionId {
		case 442: // id-M4ReportAmount -> M4ReportAmountMDT (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension M4ReportAmountMDT (%d): %w", extensionId, err)
			}
			result := M4ReportAmountMDT(v)
			return &result, nil
		}
	case "M5ConfigurationExtIEs", "M5Configuration-ExtIEs":
		switch extensionId {
		case 443: // id-M5ReportAmount -> M5ReportAmountMDT (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension M5ReportAmountMDT (%d): %w", extensionId, err)
			}
			result := M5ReportAmountMDT(v)
			return &result, nil
		}
	case "M6ConfigurationExtIEs", "M6Configuration-ExtIEs":
		switch extensionId {
		case 444: // id-M6ReportAmount -> M6ReportAmountMDT (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension M6ReportAmountMDT (%d): %w", extensionId, err)
			}
			result := M6ReportAmountMDT(v)
			return &result, nil
		}
	case "M7ConfigurationExtIEs", "M7Configuration-ExtIEs":
		switch extensionId {
		case 445: // id-M7ReportAmount -> M7ReportAmountMDT (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension M7ReportAmountMDT (%d): %w", extensionId, err)
			}
			result := M7ReportAmountMDT(v)
			return &result, nil
		}
	case "MDTConfigurationExtIEs", "MDT-Configuration-ExtIEs":
		switch extensionId {
		case 85: // id-M3Configuration -> M3Configuration
			var v M3Configuration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension M3Configuration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 86: // id-M4Configuration -> M4Configuration
			var v M4Configuration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension M4Configuration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 87: // id-M5Configuration -> M5Configuration
			var v M5Configuration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension M5Configuration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 88: // id-MDT-Location-Info -> MDT-Location-Info (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MDT-Location-Info (%d): %w", extensionId, err)
			}
			result := MDTLocationInfo{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 161: // id-M6Configuration -> M6Configuration
			var v M6Configuration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension M6Configuration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 162: // id-M7Configuration -> M7Configuration
			var v M7Configuration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension M7Configuration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 303: // id-BluetoothMeasurementConfiguration -> BluetoothMeasurementConfiguration
			var v BluetoothMeasurementConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension BluetoothMeasurementConfiguration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 304: // id-WLANMeasurementConfiguration -> WLANMeasurementConfiguration
			var v WLANMeasurementConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension WLANMeasurementConfiguration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 440: // id-SensorMeasurementConfiguration -> SensorMeasurementConfiguration
			var v SensorMeasurementConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SensorMeasurementConfiguration (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "MeNBResourceCoordinationInformationExtIEs":
		switch extensionId {
		case 322: // id-NRCGI -> NRCGI
			var v NRCGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension NRCGI (%d): %w", extensionId, err)
			}
			return &v, nil
		case 323: // id-MeNBCoordinationAssistanceInformation -> MeNBCoordinationAssistanceInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MeNBCoordinationAssistanceInformation (%d): %w", extensionId, err)
			}
			result := MeNBCoordinationAssistanceInformation(v)
			return &result, nil
		}
	case "NeighbourInformationExtIEs", "Neighbour-Information-ExtIEs":
		switch extensionId {
		case 76: // id-NeighbourTAC -> TAC (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 2, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TAC (%d): %w", extensionId, err)
			}
			result := TAC(v)
			return &result, nil
		case 94: // id-eARFCNExtension -> EARFCNExtension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(65536), int64Ptr(262143), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EARFCNExtension (%d): %w", extensionId, err)
			}
			result := EARFCNExtension(v)
			return &result, nil
		}
	case "NRFreqInfoExtIEs", "NRFreqInfo-ExtIEs":
		switch extensionId {
		case 388: // id-FrequencyShift7p5khz -> FrequencyShift7p5khz (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension FrequencyShift7p5khz (%d): %w", extensionId, err)
			}
			result := FrequencyShift7p5khz(v)
			return &result, nil
		}
	case "NRRAReportListItemExtIEs", "NRRAReportList-Item-ExtIEs":
		switch extensionId {
		case 448: // id-PSCellListContainer -> PSCellListContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PSCellListContainer (%d): %w", extensionId, err)
			}
			result := PSCellListContainer(v)
			return &result, nil
		}
	case "NRNeighbourInformationExtIEs", "NRNeighbour-Information-ExtIEs":
		switch extensionId {
		case 380: // id-CSI-RSTransmissionIndication -> CSI-RSTransmissionIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CSI-RSTransmissionIndication (%d): %w", extensionId, err)
			}
			result := CSIRSTransmissionIndication(v)
			return &result, nil
		case 389: // id-SSB-PositionsInBurst -> SSB-PositionsInBurst
			var v SSBPositionsInBurst
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SSB-PositionsInBurst (%d): %w", extensionId, err)
			}
			return &v, nil
		case 390: // id-NRCellPRACHConfig -> NRCellPRACHConfig (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCellPRACHConfig (%d): %w", extensionId, err)
			}
			result := NRCellPRACHConfig(v)
			return &result, nil
		case 433: // id-Additional-Measurement-Timing-Configuration-List -> Additional-Measurement-Timing-Configuration-List (SEQUENCE OF AdditionalMeasurementTimingConfigurationItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Additional-Measurement-Timing-Configuration-List length: %w", err)
			}
			result := make(AdditionalMeasurementTimingConfigurationList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension Additional-Measurement-Timing-Configuration-List item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "NRRadioResourceStatusExtIEs", "NRRadioResourceStatus-ExtIEs":
		switch extensionId {
		case 439: // id-MIMOPRBusageInformation -> MIMOPRBusageInformation
			var v MIMOPRBusageInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension MIMOPRBusageInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ProSeAuthorizedExtIEs", "ProSeAuthorized-ExtIEs":
		switch extensionId {
		case 149: // id-ProSeUEtoNetworkRelaying -> ProSeUEtoNetworkRelaying (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ProSeUEtoNetworkRelaying (%d): %w", extensionId, err)
			}
			result := ProSeUEtoNetworkRelaying(v)
			return &result, nil
		}
	case "RadioResourceStatusExtIEs", "RadioResourceStatus-ExtIEs":
		switch extensionId {
		case 193: // id-DL-scheduling-PDCCH-CCE-usage -> DL-scheduling-PDCCH-CCE-usage (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(100), false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension DL-scheduling-PDCCH-CCE-usage (%d): %w", extensionId, err)
			}
			result := DLSchedulingPDCCHCCEUsage(v)
			return &result, nil
		case 194: // id-UL-scheduling-PDCCH-CCE-usage -> UL-scheduling-PDCCH-CCE-usage (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(100), false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension UL-scheduling-PDCCH-CCE-usage (%d): %w", extensionId, err)
			}
			result := ULSchedulingPDCCHCCEUsage(v)
			return &result, nil
		}
	case "RelativeNarrowbandTxPowerExtIEs", "RelativeNarrowbandTxPower-ExtIEs":
		switch extensionId {
		case 148: // id-enhancedRNTP -> EnhancedRNTP
			var v EnhancedRNTP
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension EnhancedRNTP (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "RSRPMRListExtIEs", "RSRPMRList-ExtIEs":
		switch extensionId {
		case 147: // id-UEID -> UEID (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension UEID (%d): %w", extensionId, err)
			}
			result := UEID{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ServedCellExtIEs", "ServedCell-ExtIEs":
		switch extensionId {
		case 327: // id-NRNeighbourInfoToAdd -> NRNeighbour-Information (SEQUENCE OF NRNeighbourInformationElem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 1024)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRNeighbour-Information length: %w", err)
			}
			result := make(NRNeighbourInformation, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension NRNeighbour-Information item %d: %w", i, err)
				}
			}
			return &result, nil
		case 434: // id-ServedCellSpecificInfoReq-NR -> ServedCellSpecificInfoReq-NR (SEQUENCE OF ServedCellSpecificInfoReqNRItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16384)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ServedCellSpecificInfoReq-NR length: %w", err)
			}
			result := make(ServedCellSpecificInfoReqNR, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension ServedCellSpecificInfoReq-NR item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "ServedCellInformationExtIEs", "ServedCell-Information-ExtIEs":
		switch extensionId {
		case 41: // id-Number-of-Antennaports -> Number-of-Antennaports (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Number-of-Antennaports (%d): %w", extensionId, err)
			}
			result := NumberOfAntennaports(v)
			return &result, nil
		case 55: // id-PRACH-Configuration -> PRACH-Configuration
			var v PRACHConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension PRACH-Configuration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 56: // id-MBSFN-Subframe-Info -> MBSFN-Subframe-Infolist (SEQUENCE OF MBSFNSubframeInfo)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 8)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MBSFN-Subframe-Infolist length: %w", err)
			}
			result := make(MBSFNSubframeInfolist, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension MBSFN-Subframe-Infolist item %d: %w", i, err)
				}
			}
			return &result, nil
		case 70: // id-CSG-Id -> CSG-Id (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 27, 27, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CSG-Id (%d): %w", extensionId, err)
			}
			result := CSGId{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 84: // id-MultibandInfoList -> MultibandInfoList (SEQUENCE OF BandInfo)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MultibandInfoList length: %w", err)
			}
			result := make(MultibandInfoList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension MultibandInfoList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 160: // id-FreqBandIndicatorPriority -> FreqBandIndicatorPriority (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension FreqBandIndicatorPriority (%d): %w", extensionId, err)
			}
			result := FreqBandIndicatorPriority(v)
			return &result, nil
		case 180: // id-BandwidthReducedSI -> BandwidthReducedSI (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension BandwidthReducedSI (%d): %w", extensionId, err)
			}
			result := BandwidthReducedSI(v)
			return &result, nil
		case 284: // id-ProtectedEUTRAResourceIndication -> ProtectedEUTRAResourceIndication
			var v ProtectedEUTRAResourceIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension ProtectedEUTRAResourceIndication (%d): %w", extensionId, err)
			}
			return &v, nil
		case 336: // id-BPLMN-ID-Info-EUTRA -> BPLMN-ID-Info-EUTRA (SEQUENCE OF BPLMNIDInfoEUTRAItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 6)
			if err != nil {
				return nil, fmt.Errorf("decoding extension BPLMN-ID-Info-EUTRA length: %w", err)
			}
			result := make(BPLMNIDInfoEUTRA, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension BPLMN-ID-Info-EUTRA item %d: %w", i, err)
				}
			}
			return &result, nil
		case 373: // id-NPRACHConfiguration -> NPRACHConfiguration
			var v NPRACHConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension NPRACHConfiguration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 406: // id-SFN-Offset -> SFN-Offset
			var v SFNOffset
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SFN-Offset (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "SgNBResourceCoordinationInformationExtIEs":
		switch extensionId {
		case 316: // id-ECGI -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension ECGI (%d): %w", extensionId, err)
			}
			return &v, nil
		case 324: // id-SgNBCoordinationAssistanceInformation -> SgNBCoordinationAssistanceInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension SgNBCoordinationAssistanceInformation (%d): %w", extensionId, err)
			}
			result := SgNBCoordinationAssistanceInformation(v)
			return &result, nil
		}
	case "SULInformationExtIEs", "SULInformation-ExtIEs":
		switch extensionId {
		case 386: // id-CarrierList -> NRCarrierList (SEQUENCE OF NRCarrierItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 5)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCarrierList length: %w", err)
			}
			result := make(NRCarrierList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension NRCarrierList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 388: // id-FrequencyShift7p5khz -> FrequencyShift7p5khz (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension FrequencyShift7p5khz (%d): %w", extensionId, err)
			}
			result := FrequencyShift7p5khz(v)
			return &result, nil
		}
	case "TDDInfoExtIEs", "TDD-Info-ExtIEs":
		switch extensionId {
		case 97: // id-AdditionalSpecialSubframe-Info -> AdditionalSpecialSubframe-Info
			var v AdditionalSpecialSubframeInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension AdditionalSpecialSubframe-Info (%d): %w", extensionId, err)
			}
			return &v, nil
		case 94: // id-eARFCNExtension -> EARFCNExtension (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(65536), int64Ptr(262143), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EARFCNExtension (%d): %w", extensionId, err)
			}
			result := EARFCNExtension(v)
			return &result, nil
		case 179: // id-AdditionalSpecialSubframeExtension-Info -> AdditionalSpecialSubframeExtension-Info
			var v AdditionalSpecialSubframeExtensionInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension AdditionalSpecialSubframeExtension-Info (%d): %w", extensionId, err)
			}
			return &v, nil
		case 177: // id-OffsetOfNbiotChannelNumberToDL-EARFCN -> OffsetOfNbiotChannelNumberToEARFCN (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 21, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension OffsetOfNbiotChannelNumberToEARFCN (%d): %w", extensionId, err)
			}
			result := OffsetOfNbiotChannelNumberToEARFCN(v)
			return &result, nil
		case 338: // id-NBIoT-UL-DL-AlignmentOffset -> NBIoT-UL-DL-AlignmentOffset (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NBIoT-UL-DL-AlignmentOffset (%d): %w", extensionId, err)
			}
			result := NBIoTULDLAlignmentOffset(v)
			return &result, nil
		}
	case "TDDInfoNeighbourServedNRCellInformationExtIEs", "TDD-InfoNeighbourServedNRCell-Information-ExtIEs":
		switch extensionId {
		case 399: // id-IntendedTDD-DL-ULConfiguration-NR -> IntendedTDD-DL-ULConfiguration-NR (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension IntendedTDD-DL-ULConfiguration-NR (%d): %w", extensionId, err)
			}
			result := IntendedTDDDLULConfigurationNR(v)
			return &result, nil
		case 385: // id-TDDULDLConfigurationCommonNR -> TDDULDLConfigurationCommonNR (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TDDULDLConfigurationCommonNR (%d): %w", extensionId, err)
			}
			result := TDDULDLConfigurationCommonNR(v)
			return &result, nil
		case 386: // id-CarrierList -> NRCarrierList (SEQUENCE OF NRCarrierItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 5)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCarrierList length: %w", err)
			}
			result := make(NRCarrierList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension NRCarrierList item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "TraceActivationExtIEs", "TraceActivation-ExtIEs":
		switch extensionId {
		case 72: // id-MDTConfiguration -> MDT-Configuration
			var v MDTConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension MDT-Configuration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 195: // id-UEAppLayerMeasConfig -> UEAppLayerMeasConfig
			var v UEAppLayerMeasConfig
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension UEAppLayerMeasConfig (%d): %w", extensionId, err)
			}
			return &v, nil
		case 375: // id-MDTConfigurationNR -> MDT-ConfigurationNR (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MDT-ConfigurationNR (%d): %w", extensionId, err)
			}
			result := MDTConfigurationNR(v)
			return &result, nil
		}
	case "UEAggregateMaximumBitrateExtIEs", "UEAggregate-MaximumBitrate-ExtIEs":
		switch extensionId {
		case 200: // id-extended-uEaggregateMaximumBitRateDownlink -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(10000000001), int64Ptr(4000000000000), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			result := ExtendedBitRate(v)
			return &result, nil
		case 201: // id-extended-uEaggregateMaximumBitRateUplink -> ExtendedBitRate (INTEGER)
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
	case "UEContextInformationExtIEs", "UE-ContextInformation-ExtIEs":
		switch extensionId {
		case 74: // id-ManagementBasedMDTallowed -> ManagementBasedMDTallowed (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ManagementBasedMDTallowed (%d): %w", extensionId, err)
			}
			result := ManagementBasedMDTallowed(v)
			return &result, nil
		case 184: // id-UESidelinkAggregateMaximumBitRate -> UESidelinkAggregateMaximumBitRate
			var v UESidelinkAggregateMaximumBitRate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension UESidelinkAggregateMaximumBitRate (%d): %w", extensionId, err)
			}
			return &v, nil
		case 360: // id-EPCHandoverRestrictionListContainer -> EPCHandoverRestrictionListContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EPCHandoverRestrictionListContainer (%d): %w", extensionId, err)
			}
			result := EPCHandoverRestrictionListContainer(v)
			return &result, nil
		case 340: // id-AdditionalRRMPriorityIndex -> AdditionalRRMPriorityIndex (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension AdditionalRRMPriorityIndex (%d): %w", extensionId, err)
			}
			result := AdditionalRRMPriorityIndex{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 371: // id-NRUESidelinkAggregateMaximumBitRate -> NRUESidelinkAggregateMaximumBitRate
			var v NRUESidelinkAggregateMaximumBitRate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension NRUESidelinkAggregateMaximumBitRate (%d): %w", extensionId, err)
			}
			return &v, nil
		case 378: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension UERadioCapabilityID (%d): %w", extensionId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		case 408: // id-IMSvoiceEPSfallbackfrom5G -> IMSvoiceEPSfallbackfrom5G (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension IMSvoiceEPSfallbackfrom5G (%d): %w", extensionId, err)
			}
			result := IMSvoiceEPSfallbackfrom5G(v)
			return &result, nil
		}
	case "ERABsToBeSetupItemExtIEs", "E-RABs-ToBeSetup-ItemExtIEs":
		switch extensionId {
		case 171: // id-BearerType -> BearerType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension BearerType (%d): %w", extensionId, err)
			}
			result := BearerType(v)
			return &result, nil
		case 363: // id-DAPSRequestInfo -> DAPSRequestInfo
			var v DAPSRequestInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension DAPSRequestInfo (%d): %w", extensionId, err)
			}
			return &v, nil
		case 369: // id-Ethernet-Type -> Ethernet-Type (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Ethernet-Type (%d): %w", extensionId, err)
			}
			result := EthernetType(v)
			return &result, nil
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 435: // id-SecurityIndication -> SecurityIndication
			var v SecurityIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SecurityIndication (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ERABsAdmittedItemExtIEs", "E-RABs-Admitted-Item-ExtIEs":
		switch extensionId {
		case 366: // id-DAPSResponseInfo -> DAPSResponseInfo
			var v DAPSResponseInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension DAPSResponseInfo (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ERABsSubjectToStatusTransferItemExtIEs", "E-RABs-SubjectToStatusTransfer-ItemExtIEs":
		switch extensionId {
		case 91: // id-ReceiveStatusOfULPDCPSDUsExtended -> ReceiveStatusOfULPDCPSDUsExtended (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 1, 16384, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ReceiveStatusOfULPDCPSDUsExtended (%d): %w", extensionId, err)
			}
			result := ReceiveStatusOfULPDCPSDUsExtended{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 92: // id-ULCOUNTValueExtended -> COUNTValueExtended
			var v COUNTValueExtended
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension COUNTValueExtended (%d): %w", extensionId, err)
			}
			return &v, nil
		case 93: // id-DLCOUNTValueExtended -> COUNTValueExtended
			var v COUNTValueExtended
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension COUNTValueExtended (%d): %w", extensionId, err)
			}
			return &v, nil
		case 150: // id-ReceiveStatusOfULPDCPSDUsPDCP-SNlength18 -> ReceiveStatusOfULPDCPSDUsPDCP-SNlength18 (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 1, 131072, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ReceiveStatusOfULPDCPSDUsPDCP-SNlength18 (%d): %w", extensionId, err)
			}
			result := ReceiveStatusOfULPDCPSDUsPDCPSNlength18{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 151: // id-ULCOUNTValuePDCP-SNlength18 -> COUNTvaluePDCP-SNlength18
			var v COUNTvaluePDCPSNlength18
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension COUNTvaluePDCP-SNlength18 (%d): %w", extensionId, err)
			}
			return &v, nil
		case 152: // id-DLCOUNTValuePDCP-SNlength18 -> COUNTvaluePDCP-SNlength18
			var v COUNTvaluePDCPSNlength18
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension COUNTvaluePDCP-SNlength18 (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "CellInformationItemExtIEs", "CellInformation-Item-ExtIEs":
		switch extensionId {
		case 61: // id-ABSInformation -> ABSInformation
			var v ABSInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension ABSInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		case 62: // id-InvokeIndication -> InvokeIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension InvokeIndication (%d): %w", extensionId, err)
			}
			result := InvokeIndication(v)
			return &result, nil
		case 99: // id-IntendedULDLConfiguration -> SubframeAssignment (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 7, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension SubframeAssignment (%d): %w", extensionId, err)
			}
			result := SubframeAssignment(v)
			return &result, nil
		case 100: // id-ExtendedULInterferenceOverloadInfo -> ExtendedULInterferenceOverloadInfo
			var v ExtendedULInterferenceOverloadInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedULInterferenceOverloadInfo (%d): %w", extensionId, err)
			}
			return &v, nil
		case 108: // id-CoMPInformation -> CoMPInformation
			var v CoMPInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension CoMPInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		case 106: // id-DynamicDLTransmissionInformation -> DynamicDLTransmissionInformation
			var v DynamicDLTransmissionInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension DynamicDLTransmissionInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ServedCellsToModifyItemExtIEs", "ServedCellsToModify-Item-ExtIEs":
		switch extensionId {
		case 59: // id-DeactivationIndication -> DeactivationIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension DeactivationIndication (%d): %w", extensionId, err)
			}
			result := DeactivationIndication(v)
			return &result, nil
		case 328: // id-NRNeighbourInfoToModify -> NRNeighbour-Information (SEQUENCE OF NRNeighbourInformationElem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 1024)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRNeighbour-Information length: %w", err)
			}
			result := make(NRNeighbourInformation, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension NRNeighbour-Information item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "CellMeasurementResultItemExtIEs", "CellMeasurementResult-Item-ExtIEs":
		switch extensionId {
		case 42: // id-CompositeAvailableCapacityGroup -> CompositeAvailableCapacityGroup
			var v CompositeAvailableCapacityGroup
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension CompositeAvailableCapacityGroup (%d): %w", extensionId, err)
			}
			return &v, nil
		case 63: // id-ABS-Status -> ABS-Status
			var v ABSStatus
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension ABS-Status (%d): %w", extensionId, err)
			}
			return &v, nil
		case 110: // id-RSRPMRList -> RSRPMRList (SEQUENCE OF RSRPMRListElem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 128)
			if err != nil {
				return nil, fmt.Errorf("decoding extension RSRPMRList length: %w", err)
			}
			result := make(RSRPMRList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension RSRPMRList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 146: // id-CSIReportList -> CSIReportList (SEQUENCE OF CSIReportListElem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 128)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CSIReportList length: %w", err)
			}
			result := make(CSIReportList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension CSIReportList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 170: // id-CellReportingIndicator -> CellReportingIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CellReportingIndicator (%d): %w", extensionId, err)
			}
			result := CellReportingIndicator(v)
			return &result, nil
		case 417: // id-MeasurementResultforNRCellsPossiblyAggregated -> MeasurementResultforNRCellsPossiblyAggregated (SEQUENCE OF MeasurementResultforNRCellsPossiblyAggregatedItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MeasurementResultforNRCellsPossiblyAggregated length: %w", err)
			}
			result := make(MeasurementResultforNRCellsPossiblyAggregated, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension MeasurementResultforNRCellsPossiblyAggregated item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "ERABsToBeAddedItemSCGBearerExtIEs", "E-RABs-ToBeAdded-Item-SCG-BearerExtIEs":
		switch extensionId {
		case 166: // id-Correlation-ID -> Correlation-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Correlation-ID (%d): %w", extensionId, err)
			}
			result := CorrelationID(v)
			return &result, nil
		case 167: // id-SIPTO-Correlation-ID -> Correlation-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Correlation-ID (%d): %w", extensionId, err)
			}
			result := CorrelationID(v)
			return &result, nil
		case 171: // id-BearerType -> BearerType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension BearerType (%d): %w", extensionId, err)
			}
			result := BearerType(v)
			return &result, nil
		case 369: // id-Ethernet-Type -> Ethernet-Type (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Ethernet-Type (%d): %w", extensionId, err)
			}
			result := EthernetType(v)
			return &result, nil
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ERABsToBeAddedItemSplitBearerExtIEs", "E-RABs-ToBeAdded-Item-Split-BearerExtIEs":
		switch extensionId {
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ERABsAdmittedToBeAddedItemSCGBearerExtIEs", "E-RABs-Admitted-ToBeAdded-Item-SCG-BearerExtIEs":
		switch extensionId {
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ERABsAdmittedToBeAddedItemSplitBearerExtIEs", "E-RABs-Admitted-ToBeAdded-Item-Split-BearerExtIEs":
		switch extensionId {
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ERABsToBeAddedModReqItemSCGBearerExtIEs", "E-RABs-ToBeAdded-ModReqItem-SCG-BearerExtIEs":
		switch extensionId {
		case 166: // id-Correlation-ID -> Correlation-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Correlation-ID (%d): %w", extensionId, err)
			}
			result := CorrelationID(v)
			return &result, nil
		case 167: // id-SIPTO-Correlation-ID -> Correlation-ID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Correlation-ID (%d): %w", extensionId, err)
			}
			result := CorrelationID(v)
			return &result, nil
		case 171: // id-BearerType -> BearerType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension BearerType (%d): %w", extensionId, err)
			}
			result := BearerType(v)
			return &result, nil
		case 369: // id-Ethernet-Type -> Ethernet-Type (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Ethernet-Type (%d): %w", extensionId, err)
			}
			result := EthernetType(v)
			return &result, nil
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ERABsToBeAddedModReqItemSplitBearerExtIEs", "E-RABs-ToBeAdded-ModReqItem-Split-BearerExtIEs":
		switch extensionId {
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ERABsAdmittedToBeAddedModAckItemSCGBearerExtIEs", "E-RABs-Admitted-ToBeAdded-ModAckItem-SCG-BearerExtIEs":
		switch extensionId {
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ERABsAdmittedToBeAddedModAckItemSplitBearerExtIEs", "E-RABs-Admitted-ToBeAdded-ModAckItem-Split-BearerExtIEs":
		switch extensionId {
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "UEContextInformationRetrieveExtIEs", "UE-ContextInformationRetrieve-ExtIEs":
		switch extensionId {
		case 184: // id-UESidelinkAggregateMaximumBitRate -> UESidelinkAggregateMaximumBitRate
			var v UESidelinkAggregateMaximumBitRate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension UESidelinkAggregateMaximumBitRate (%d): %w", extensionId, err)
			}
			return &v, nil
		case 340: // id-AdditionalRRMPriorityIndex -> AdditionalRRMPriorityIndex (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension AdditionalRRMPriorityIndex (%d): %w", extensionId, err)
			}
			result := AdditionalRRMPriorityIndex{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 360: // id-EPCHandoverRestrictionListContainer -> EPCHandoverRestrictionListContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EPCHandoverRestrictionListContainer (%d): %w", extensionId, err)
			}
			result := EPCHandoverRestrictionListContainer(v)
			return &result, nil
		case 371: // id-NRUESidelinkAggregateMaximumBitRate -> NRUESidelinkAggregateMaximumBitRate
			var v NRUESidelinkAggregateMaximumBitRate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension NRUESidelinkAggregateMaximumBitRate (%d): %w", extensionId, err)
			}
			return &v, nil
		case 378: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension UERadioCapabilityID (%d): %w", extensionId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		case 408: // id-IMSvoiceEPSfallbackfrom5G -> IMSvoiceEPSfallbackfrom5G (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension IMSvoiceEPSfallbackfrom5G (%d): %w", extensionId, err)
			}
			result := IMSvoiceEPSfallbackfrom5G(v)
			return &result, nil
		}
	case "ERABsToBeSetupRetrieveItemExtIEs", "E-RABs-ToBeSetupRetrieve-ItemExtIEs":
		switch extensionId {
		case 185: // id-uL-GTPtunnelEndpoint -> GTPtunnelEndpoint
			var v GTPtunnelEndpoint
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension GTPtunnelEndpoint (%d): %w", extensionId, err)
			}
			return &v, nil
		case 306: // id-dL-Forwarding -> DL-Forwarding (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension DL-Forwarding (%d): %w", extensionId, err)
			}
			result := DLForwarding(v)
			return &result, nil
		case 369: // id-Ethernet-Type -> Ethernet-Type (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Ethernet-Type (%d): %w", extensionId, err)
			}
			result := EthernetType(v)
			return &result, nil
		case 435: // id-SecurityIndication -> SecurityIndication
			var v SecurityIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SecurityIndication (%d): %w", extensionId, err)
			}
			return &v, nil
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ERABsToBeAddedSgNBAddReqItemSgNBPDCPpresentExtIEs", "E-RABs-ToBeAdded-SgNBAddReq-Item-SgNBPDCPpresentExtIEs":
		switch extensionId {
		case 317: // id-RLCMode-transferred -> RLCMode (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension RLCMode (%d): %w", extensionId, err)
			}
			result := RLCMode(v)
			return &result, nil
		case 171: // id-BearerType -> BearerType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension BearerType (%d): %w", extensionId, err)
			}
			result := BearerType(v)
			return &result, nil
		case 369: // id-Ethernet-Type -> Ethernet-Type (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Ethernet-Type (%d): %w", extensionId, err)
			}
			result := EthernetType(v)
			return &result, nil
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 435: // id-SecurityIndication -> SecurityIndication
			var v SecurityIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SecurityIndication (%d): %w", extensionId, err)
			}
			return &v, nil
		case 413: // id-SourceNodeDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ERABsToBeAddedSgNBAddReqItemSgNBPDCPnotpresentExtIEs", "E-RABs-ToBeAdded-SgNBAddReq-Item-SgNBPDCPnotpresentExtIEs":
		switch extensionId {
		case 302: // id-uLpDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		case 311: // id-dLPDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		case 315: // id-duplicationActivation -> DuplicationActivation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension DuplicationActivation (%d): %w", extensionId, err)
			}
			result := DuplicationActivation(v)
			return &result, nil
		}
	case "ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPpresentExtIEs", "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item-SgNBPDCPpresentExtIEs":
		switch extensionId {
		case 302: // id-uLpDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		case 311: // id-dLPDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 436: // id-SecurityResult -> SecurityResult
			var v SecurityResult
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SecurityResult (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPnotpresentExtIEs", "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item-SgNBPDCPnotpresentExtIEs":
		switch extensionId {
		case 314: // id-lCID -> LCID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(32), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension LCID (%d): %w", extensionId, err)
			}
			result := LCID(v)
			return &result, nil
		}
	case "UEContextInformationSgNBModReqExtIEs", "UE-ContextInformationSgNBModReqExtIEs":
		switch extensionId {
		case 275: // id-SubscriberProfileIDforRFP -> SubscriberProfileIDforRFP (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(256), false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension SubscriberProfileIDforRFP (%d): %w", extensionId, err)
			}
			result := SubscriberProfileIDforRFP(v)
			return &result, nil
		case 340: // id-AdditionalRRMPriorityIndex -> AdditionalRRMPriorityIndex (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension AdditionalRRMPriorityIndex (%d): %w", extensionId, err)
			}
			result := AdditionalRRMPriorityIndex{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 341: // id-LowerLayerPresenceStatusChange -> LowerLayerPresenceStatusChange (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension LowerLayerPresenceStatusChange (%d): %w", extensionId, err)
			}
			result := LowerLayerPresenceStatusChange(v)
			return &result, nil
		}
	case "ERABsToBeAddedSgNBModReqItemSgNBPDCPpresentExtIEs", "E-RABs-ToBeAdded-SgNBModReq-Item-SgNBPDCPpresentExtIEs":
		switch extensionId {
		case 317: // id-RLCMode-transferred -> RLCMode (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension RLCMode (%d): %w", extensionId, err)
			}
			result := RLCMode(v)
			return &result, nil
		case 171: // id-BearerType -> BearerType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension BearerType (%d): %w", extensionId, err)
			}
			result := BearerType(v)
			return &result, nil
		case 369: // id-Ethernet-Type -> Ethernet-Type (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Ethernet-Type (%d): %w", extensionId, err)
			}
			result := EthernetType(v)
			return &result, nil
		case 435: // id-SecurityIndication -> SecurityIndication
			var v SecurityIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SecurityIndication (%d): %w", extensionId, err)
			}
			return &v, nil
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ERABsToBeAddedSgNBModReqItemSgNBPDCPnotpresentExtIEs", "E-RABs-ToBeAdded-SgNBModReq-Item-SgNBPDCPnotpresentExtIEs":
		switch extensionId {
		case 302: // id-uLpDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		case 311: // id-dLPDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		case 315: // id-duplicationActivation -> DuplicationActivation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension DuplicationActivation (%d): %w", extensionId, err)
			}
			result := DuplicationActivation(v)
			return &result, nil
		}
	case "ERABsToBeModifiedSgNBModReqItemSgNBPDCPpresentExtIEs", "E-RABs-ToBeModified-SgNBModReq-Item-SgNBPDCPpresentExtIEs":
		switch extensionId {
		case 300: // id-RLC-Status -> RLC-Status
			var v RLCStatus
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension RLC-Status (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ERABsToBeModifiedSgNBModReqItemSgNBPDCPnotpresentExtIEs", "E-RABs-ToBeModified-SgNBModReq-Item-SgNBPDCPnotpresentExtIEs":
		switch extensionId {
		case 302: // id-uLpDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		case 311: // id-dLPDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		case 313: // id-secondarymeNBULGTPTEIDatPDCP -> GTPtunnelEndpoint
			var v GTPtunnelEndpoint
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension GTPtunnelEndpoint (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPpresentExtIEs", "E-RABs-Admitted-ToBeAdded-SgNBModAck-Item-SgNBPDCPpresentExtIEs":
		switch extensionId {
		case 302: // id-uLpDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		case 311: // id-dLPDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		case 436: // id-SecurityResult -> SecurityResult
			var v SecurityResult
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SecurityResult (%d): %w", extensionId, err)
			}
			return &v, nil
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPnotpresentExtIEs", "E-RABs-Admitted-ToBeAdded-SgNBModAck-Item-SgNBPDCPnotpresentExtIEs":
		switch extensionId {
		case 314: // id-lCID -> LCID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(32), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension LCID (%d): %w", extensionId, err)
			}
			result := LCID(v)
			return &result, nil
		}
	case "ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPpresentExtIEs", "E-RABs-Admitted-ToBeModified-SgNBModAck-Item-SgNBPDCPpresentExtIEs":
		switch extensionId {
		case 302: // id-uLpDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		case 311: // id-dLPDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		}
	case "ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPnotpresentExtIEs", "E-RABs-Admitted-ToBeModified-SgNBModAck-Item-SgNBPDCPnotpresentExtIEs":
		switch extensionId {
		case 312: // id-secondarysgNBDLGTPTEIDatPDCP -> GTPtunnelEndpoint
			var v GTPtunnelEndpoint
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension GTPtunnelEndpoint (%d): %w", extensionId, err)
			}
			return &v, nil
		case 300: // id-RLC-Status -> RLC-Status
			var v RLCStatus
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension RLC-Status (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ERABsToBeReleasedSgNBModReqdItemExtIEs", "E-RABs-ToBeReleased-SgNBModReqd-ItemExtIEs":
		switch extensionId {
		case 317: // id-RLCMode-transferred -> RLCMode (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension RLCMode (%d): %w", extensionId, err)
			}
			result := RLCMode(v)
			return &result, nil
		}
	case "ERABsToBeModifiedSgNBModReqdItemSgNBPDCPpresentExtIEs", "E-RABs-ToBeModified-SgNBModReqd-Item-SgNBPDCPpresentExtIEs":
		switch extensionId {
		case 302: // id-uLpDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		case 311: // id-dLPDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		case 325: // id-new-drb-ID-req -> NewDRBIDrequest (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NewDRBIDrequest (%d): %w", extensionId, err)
			}
			result := NewDRBIDrequest(v)
			return &result, nil
		}
	case "ERABsToBeModifiedSgNBModReqdItemSgNBPDCPnotpresentExtIEs", "E-RABs-ToBeModified-SgNBModReqd-Item-SgNBPDCPnotpresentExtIEs":
		switch extensionId {
		case 300: // id-RLC-Status -> RLC-Status
			var v RLCStatus
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension RLC-Status (%d): %w", extensionId, err)
			}
			return &v, nil
		case 314: // id-lCID -> LCID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(32), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension LCID (%d): %w", extensionId, err)
			}
			result := LCID(v)
			return &result, nil
		}
	case "ERABsAdmittedToBeModifiedSgNBModConfItemSgNBPDCPnotpresentExtIEs", "E-RABs-AdmittedToBeModified-SgNBModConf-Item-SgNBPDCPnotpresentExtIEs":
		switch extensionId {
		case 302: // id-uLpDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		case 311: // id-dLPDCPSnLength -> PDCPSnLength (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PDCPSnLength (%d): %w", extensionId, err)
			}
			result := PDCPSnLength(v)
			return &result, nil
		}
	case "ERABsToBeReleasedSgNBChaConfItemSgNBPDCPpresentExtIEs", "E-RABs-ToBeReleased-SgNBChaConf-Item-SgNBPDCPpresentExtIEs":
		switch extensionId {
		case 441: // id-AdditionalListofForwardingGTPTunnelEndpoint -> AdditionalListofForwardingGTPTunnelEndpoint (SEQUENCE OF AdditionalListofForwardingGTPTunnelEndpointItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 7)
			if err != nil {
				return nil, fmt.Errorf("decoding extension AdditionalListofForwardingGTPTunnelEndpoint length: %w", err)
			}
			result := make(AdditionalListofForwardingGTPTunnelEndpoint, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension AdditionalListofForwardingGTPTunnelEndpoint item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "EnGNBServedCellsExtIEs", "En-gNBServedCells-ExtIEs":
		switch extensionId {
		case 434: // id-ServedCellSpecificInfoReq-NR -> ServedCellSpecificInfoReq-NR (SEQUENCE OF ServedCellSpecificInfoReqNRItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16384)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ServedCellSpecificInfoReq-NR length: %w", err)
			}
			result := make(ServedCellSpecificInfoReqNR, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension ServedCellSpecificInfoReq-NR item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "ServedNRCellInformationExtIEs", "ServedNRCell-Information-ExtIEs":
		switch extensionId {
		case 337: // id-BPLMN-ID-Info-NR -> BPLMN-ID-Info-NR (SEQUENCE OF BPLMNIDInfoNRItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 12)
			if err != nil {
				return nil, fmt.Errorf("decoding extension BPLMN-ID-Info-NR length: %w", err)
			}
			result := make(BPLMNIDInfoNR, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension BPLMN-ID-Info-NR item %d: %w", i, err)
				}
			}
			return &result, nil
		case 389: // id-SSB-PositionsInBurst -> SSB-PositionsInBurst
			var v SSBPositionsInBurst
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SSB-PositionsInBurst (%d): %w", extensionId, err)
			}
			return &v, nil
		case 390: // id-NRCellPRACHConfig -> NRCellPRACHConfig (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCellPRACHConfig (%d): %w", extensionId, err)
			}
			result := NRCellPRACHConfig(v)
			return &result, nil
		case 380: // id-CSI-RSTransmissionIndication -> CSI-RSTransmissionIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CSI-RSTransmissionIndication (%d): %w", extensionId, err)
			}
			result := CSIRSTransmissionIndication(v)
			return &result, nil
		case 406: // id-SFN-Offset -> SFN-Offset
			var v SFNOffset
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SFN-Offset (%d): %w", extensionId, err)
			}
			return &v, nil
		case 433: // id-Additional-Measurement-Timing-Configuration-List -> Additional-Measurement-Timing-Configuration-List (SEQUENCE OF AdditionalMeasurementTimingConfigurationItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 16)
			if err != nil {
				return nil, fmt.Errorf("decoding extension Additional-Measurement-Timing-Configuration-List length: %w", err)
			}
			result := make(AdditionalMeasurementTimingConfigurationList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension Additional-Measurement-Timing-Configuration-List item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "FDDInfoServedNRCellInformationExtIEs", "FDD-InfoServedNRCell-Information-ExtIEs":
		switch extensionId {
		case 387: // id-ULCarrierList -> NRCarrierList (SEQUENCE OF NRCarrierItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 5)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCarrierList length: %w", err)
			}
			result := make(NRCarrierList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension NRCarrierList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 381: // id-DLCarrierList -> NRCarrierList (SEQUENCE OF NRCarrierItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 5)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCarrierList length: %w", err)
			}
			result := make(NRCarrierList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension NRCarrierList item %d: %w", i, err)
				}
			}
			return &result, nil
		}
	case "TDDInfoServedNRCellInformationExtIEs", "TDD-InfoServedNRCell-Information-ExtIEs":
		switch extensionId {
		case 385: // id-TDDULDLConfigurationCommonNR -> TDDULDLConfigurationCommonNR (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TDDULDLConfigurationCommonNR (%d): %w", extensionId, err)
			}
			result := TDDULDLConfigurationCommonNR(v)
			return &result, nil
		case 386: // id-CarrierList -> NRCarrierList (SEQUENCE OF NRCarrierItem)
			seqLen, err := per.DecodeConstrainedWholeNumberAligned(bb, 1, 5)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCarrierList length: %w", err)
			}
			result := make(NRCarrierList, seqLen)
			for i := int64(0); i < seqLen; i++ {
				if err := result[i].UnmarshalAPERFrom(bb); err != nil {
					return nil, fmt.Errorf("decoding extension NRCarrierList item %d: %w", i, err)
				}
			}
			return &result, nil
		case 399: // id-IntendedTDD-DL-ULConfiguration-NR -> IntendedTDD-DL-ULConfiguration-NR (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension IntendedTDD-DL-ULConfiguration-NR (%d): %w", extensionId, err)
			}
			result := IntendedTDDDLULConfigurationNR(v)
			return &result, nil
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
	"AccessAndMobilityIndication.ProtocolIEs":                         "AccessAndMobilityIndication-IEs",
	"CPCCancel.ProtocolIEs":                                           "CPC-cancel-IEs",
	"CellActivationFailure.ProtocolIEs":                               "CellActivationFailure-IEs",
	"CellActivationRequest.ProtocolIEs":                               "CellActivationRequest-IEs",
	"CellActivationResponse.ProtocolIEs":                              "CellActivationResponse-IEs",
	"CellTrafficTrace.ProtocolIEs":                                    "CellTrafficTraceIEs",
	"CompleteFailureCauseInformationItem.MeasurementFailureCauseList": "MeasurementFailureCause-ItemIEs",
	"ConditionalHandoverCancel.ProtocolIEs":                           "ConditionalHandoverCancel-IEs",
	"DataForwardingAddressIndication.ProtocolIEs":                     "DataForwardingAddressIndication-IEs",
	"DeactivateTrace.ProtocolIEs":                                     "DeactivateTraceIEs",
	"ENBConfigurationUpdate.ProtocolIEs":                              "ENBConfigurationUpdate-IEs",
	"ENBConfigurationUpdateAcknowledge.ProtocolIEs":                   "ENBConfigurationUpdateAcknowledge-IEs",
	"ENBConfigurationUpdateFailure.ProtocolIEs":                       "ENBConfigurationUpdateFailure-IEs",
	"ENDCCellActivationFailure.ProtocolIEs":                           "ENDCCellActivationFailure-IEs",
	"ENDCCellActivationRequest.ProtocolIEs":                           "ENDCCellActivationRequest-IEs",
	"ENDCCellActivationResponse.ProtocolIEs":                          "ENDCCellActivationResponse-IEs",
	"ENDCConfigurationTransfer.ProtocolIEs":                           "ENDCConfigurationTransfer-IEs",
	"ENDCConfigurationUpdate.ProtocolIEs":                             "ENDCConfigurationUpdate-IEs",
	"ENDCConfigurationUpdateAcknowledge.ProtocolIEs":                  "ENDCConfigurationUpdateAcknowledge-IEs",
	"ENDCConfigurationUpdateFailure.ProtocolIEs":                      "ENDCConfigurationUpdateFailure-IEs",
	"ENDCPartialResetConfirm.ProtocolIEs":                             "ENDCPartialResetConfirm-IEs",
	"ENDCPartialResetRequired.ProtocolIEs":                            "ENDCPartialResetRequired-IEs",
	"ENDCResourceStatusFailure.ProtocolIEs":                           "ENDCResourceStatusFailure-IEs",
	"ENDCResourceStatusRequest.ProtocolIEs":                           "ENDCResourceStatusRequest-IEs",
	"ENDCResourceStatusResponse.ProtocolIEs":                          "ENDCResourceStatusResponse-IEs",
	"ENDCResourceStatusUpdate.ProtocolIEs":                            "ENDCResourceStatusUpdate-IEs",
	"ENDCX2RemovalFailure.ProtocolIEs":                                "ENDCX2RemovalFailure-IEs",
	"ENDCX2RemovalRequest.ProtocolIEs":                                "ENDCX2RemovalRequest-IEs",
	"ENDCX2RemovalResponse.ProtocolIEs":                               "ENDCX2RemovalResponse-IEs",
	"ENDCX2SetupFailure.ProtocolIEs":                                  "ENDCX2SetupFailure-IEs",
	"ENDCX2SetupRequest.ProtocolIEs":                                  "ENDCX2SetupRequest-IEs",
	"ENDCX2SetupResponse.ProtocolIEs":                                 "ENDCX2SetupResponse-IEs",
	"EUTRANRCellResourceCoordinationRequest.ProtocolIEs":              "EUTRANRCellResourceCoordinationRequest-IEs",
	"EUTRANRCellResourceCoordinationResponse.ProtocolIEs":             "EUTRANRCellResourceCoordinationResponse-IEs",
	"EarlyStatusTransfer.ProtocolIEs":                                 "EarlyStatusTransfer-IEs",
	"ErrorIndication.ProtocolIEs":                                     "ErrorIndication-IEs",
	"F1CTrafficTransfer.ProtocolIEs":                                  "F1CTrafficTransfer-IEs",
	"GNBStatusIndication.ProtocolIEs":                                 "GNBStatusIndicationIEs",
	"HandoverCancel.ProtocolIEs":                                      "HandoverCancel-IEs",
	"HandoverPreparationFailure.ProtocolIEs":                          "HandoverPreparationFailure-IEs",
	"HandoverReport.ProtocolIEs":                                      "HandoverReport-IEs",
	"HandoverRequest.ProtocolIEs":                                     "HandoverRequest-IEs",
	"HandoverRequestAcknowledge.ProtocolIEs":                          "HandoverRequestAcknowledge-IEs",
	"HandoverSuccess.ProtocolIEs":                                     "HandoverSuccess-IEs",
	"InitiatingNodeTypeEndcConfigUpdate.InitENB":                      "ENB-ENDCConfigUpdateIEs",
	"InitiatingNodeTypeEndcConfigUpdate.InitEnGNB":                    "En-gNB-ENDCConfigUpdateIEs",
	"InitiatingNodeTypeEndcX2Removal.InitENB":                         "ENB-ENDCX2RemovalReqIEs",
	"InitiatingNodeTypeEndcX2Removal.InitEnGNB":                       "En-gNB-ENDCX2RemovalReqIEs",
	"InitiatingNodeTypeEndcX2Setup.InitENB":                           "ENB-ENDCX2SetupReqIEs",
	"InitiatingNodeTypeEndcX2Setup.InitEnGNB":                         "En-gNB-ENDCX2SetupReqIEs",
	"InitiatingNodeTypeEutranrCellResourceCoordination.InitiateENB":   "ENB-EUTRA-NRCellResourceCoordinationReqIEs",
	"InitiatingNodeTypeEutranrCellResourceCoordination.InitiateEnGNB": "En-gNB-EUTRA-NRCellResourceCoordinationReqIEs",
	"LoadInformation.ProtocolIEs":                                     "LoadInformation-IEs",
	"MeasurementInitiationResultItem.MeasurementFailureCauseList":     "MeasurementFailureCause-ItemIEs",
	"MobilityChangeAcknowledge.ProtocolIEs":                           "MobilityChangeAcknowledge-IEs",
	"MobilityChangeFailure.ProtocolIEs":                               "MobilityChangeFailure-IEs",
	"MobilityChangeRequest.ProtocolIEs":                               "MobilityChangeRequest-IEs",
	"RLFIndication.ProtocolIEs":                                       "RLFIndication-IEs",
	"RRCTransfer.ProtocolIEs":                                         "RRCTransfer-IEs",
	"RachIndication.ProtocolIEs":                                      "RachIndication-IEs",
	"ResetRequest.ProtocolIEs":                                        "ResetRequest-IEs",
	"ResetResponse.ProtocolIEs":                                       "ResetResponse-IEs",
	"ResourceStatusFailure.ProtocolIEs":                               "ResourceStatusFailure-IEs",
	"ResourceStatusRequest.ProtocolIEs":                               "ResourceStatusRequest-IEs",
	"ResourceStatusResponse.ProtocolIEs":                              "ResourceStatusResponse-IEs",
	"ResourceStatusUpdate.ProtocolIEs":                                "ResourceStatusUpdate-IEs",
	"RespondingNodeTypeEndcConfigUpdate.RespondEnGNB":                 "En-gNB-ENDCConfigUpdateAckIEs",
	"RespondingNodeTypeEndcX2Removal.RespondENB":                      "ENB-ENDCX2RemovalReqAckIEs",
	"RespondingNodeTypeEndcX2Removal.RespondEnGNB":                    "En-gNB-ENDCX2RemovalReqAckIEs",
	"RespondingNodeTypeEndcX2Setup.RespondENB":                        "ENB-ENDCX2SetupReqAckIEs",
	"RespondingNodeTypeEndcX2Setup.RespondEnGNB":                      "En-gNB-ENDCX2SetupReqAckIEs",
	"RespondingNodeTypeEutranrCellResourceCoordination.RespondENB":    "ENB-EUTRA-NRCellResourceCoordinationReqAckIEs",
	"RespondingNodeTypeEutranrCellResourceCoordination.RespondEnGNB":  "En-gNB-EUTRA-NRCellResourceCoordinationReqAckIEs",
	"RetrieveUEContextFailure.ProtocolIEs":                            "RetrieveUEContextFailure-IEs",
	"RetrieveUEContextRequest.ProtocolIEs":                            "RetrieveUEContextRequest-IEs",
	"RetrieveUEContextResponse.ProtocolIEs":                           "RetrieveUEContextResponse-IEs",
	"SCGFailureInformationReport.ProtocolIEs":                         "SCGFailureInformationReport-IEs",
	"SCGFailureTransfer.ProtocolIEs":                                  "SCGFailureTransfer-IEs",
	"SNStatusTransfer.ProtocolIEs":                                    "SNStatusTransfer-IEs",
	"SeNBAdditionRequest.ProtocolIEs":                                 "SeNBAdditionRequest-IEs",
	"SeNBAdditionRequestAcknowledge.ProtocolIEs":                      "SeNBAdditionRequestAcknowledge-IEs",
	"SeNBAdditionRequestReject.ProtocolIEs":                           "SeNBAdditionRequestReject-IEs",
	"SeNBCounterCheckRequest.ProtocolIEs":                             "SeNBCounterCheckRequest-IEs",
	"SeNBModificationConfirm.ProtocolIEs":                             "SeNBModificationConfirm-IEs",
	"SeNBModificationRefuse.ProtocolIEs":                              "SeNBModificationRefuse-IEs",
	"SeNBModificationRequest.ProtocolIEs":                             "SeNBModificationRequest-IEs",
	"SeNBModificationRequestAcknowledge.ProtocolIEs":                  "SeNBModificationRequestAcknowledge-IEs",
	"SeNBModificationRequestReject.ProtocolIEs":                       "SeNBModificationRequestReject-IEs",
	"SeNBModificationRequired.ProtocolIEs":                            "SeNBModificationRequired-IEs",
	"SeNBReconfigurationComplete.ProtocolIEs":                         "SeNBReconfigurationComplete-IEs",
	"SeNBReleaseConfirm.ProtocolIEs":                                  "SeNBReleaseConfirm-IEs",
	"SeNBReleaseRequest.ProtocolIEs":                                  "SeNBReleaseRequest-IEs",
	"SeNBReleaseRequired.ProtocolIEs":                                 "SeNBReleaseRequired-IEs",
	"SecondaryRATDataUsageReport.ProtocolIEs":                         "SecondaryRATDataUsageReport-IEs",
	"SecondaryRATUsageReportItem.ERABUsageReportList":                 "E-RABUsageReport-ItemIEs",
	"SgNBActivityNotification.ProtocolIEs":                            "SgNBActivityNotification-IEs",
	"SgNBAdditionRequest.ProtocolIEs":                                 "SgNBAdditionRequest-IEs",
	"SgNBAdditionRequestAcknowledge.ProtocolIEs":                      "SgNBAdditionRequestAcknowledge-IEs",
	"SgNBAdditionRequestReject.ProtocolIEs":                           "SgNBAdditionRequestReject-IEs",
	"SgNBChangeConfirm.ProtocolIEs":                                   "SgNBChangeConfirm-IEs",
	"SgNBChangeRefuse.ProtocolIEs":                                    "SgNBChangeRefuse-IEs",
	"SgNBChangeRequired.ProtocolIEs":                                  "SgNBChangeRequired-IEs",
	"SgNBCounterCheckRequest.ProtocolIEs":                             "SgNBCounterCheckRequest-IEs",
	"SgNBModificationConfirm.ProtocolIEs":                             "SgNBModificationConfirm-IEs",
	"SgNBModificationRefuse.ProtocolIEs":                              "SgNBModificationRefuse-IEs",
	"SgNBModificationRequest.ProtocolIEs":                             "SgNBModificationRequest-IEs",
	"SgNBModificationRequestAcknowledge.ProtocolIEs":                  "SgNBModificationRequestAcknowledge-IEs",
	"SgNBModificationRequestReject.ProtocolIEs":                       "SgNBModificationRequestReject-IEs",
	"SgNBModificationRequired.ProtocolIEs":                            "SgNBModificationRequired-IEs",
	"SgNBReconfigurationComplete.ProtocolIEs":                         "SgNBReconfigurationComplete-IEs",
	"SgNBReleaseConfirm.ProtocolIEs":                                  "SgNBReleaseConfirm-IEs",
	"SgNBReleaseRequest.ProtocolIEs":                                  "SgNBReleaseRequest-IEs",
	"SgNBReleaseRequestAcknowledge.ProtocolIEs":                       "SgNBReleaseRequestAcknowledge-IEs",
	"SgNBReleaseRequestReject.ProtocolIEs":                            "SgNBReleaseRequestReject-IEs",
	"SgNBReleaseRequired.ProtocolIEs":                                 "SgNBReleaseRequired-IEs",
	"TraceStart.ProtocolIEs":                                          "TraceStartIEs",
	"UEContextInformation.ERABsToBeSetupList":                         "E-RABs-ToBeSetup-ItemIEs",
	"UEContextInformationRetrieve.ERABsToBeSetupListRetrieve":         "E-RABs-ToBeSetupRetrieve-ItemIEs",
	"UEContextInformationSeNBModReq.ERABsToBeAdded":                   "E-RABs-ToBeAdded-ModReqItemIEs",
	"UEContextInformationSeNBModReq.ERABsToBeModified":                "E-RABs-ToBeModified-ModReqItemIEs",
	"UEContextInformationSeNBModReq.ERABsToBeReleased":                "E-RABs-ToBeReleased-ModReqItemIEs",
	"UEContextInformationSgNBModReq.ERABsToBeAdded":                   "E-RABs-ToBeAdded-SgNBModReq-ItemIEs",
	"UEContextInformationSgNBModReq.ERABsToBeModified":                "E-RABs-ToBeModified-SgNBModReq-ItemIEs",
	"UEContextInformationSgNBModReq.ERABsToBeReleased":                "E-RABs-ToBeReleased-SgNBModReq-ItemIEs",
	"UEContextRelease.ProtocolIEs":                                    "UEContextRelease-IEs",
	"UERadioCapabilityIDMappingRequest.ProtocolIEs":                   "UERadioCapabilityIDMappingRequestIEs",
	"UERadioCapabilityIDMappingResponse.ProtocolIEs":                  "UERadioCapabilityIDMappingResponseIEs",
	"X2APMessageTransfer.ProtocolIEs":                                 "X2APMessageTransfer-IEs",
	"X2Release.ProtocolIEs":                                           "X2Release-IEs",
	"X2RemovalFailure.ProtocolIEs":                                    "X2RemovalFailure-IEs",
	"X2RemovalRequest.ProtocolIEs":                                    "X2RemovalRequest-IEs",
	"X2RemovalResponse.ProtocolIEs":                                   "X2RemovalResponse-IEs",
	"X2SetupFailure.ProtocolIEs":                                      "X2SetupFailure-IEs",
	"X2SetupRequest.ProtocolIEs":                                      "X2SetupRequest-IEs",
	"X2SetupResponse.ProtocolIEs":                                     "X2SetupResponse-IEs",
}

var protocolIETypeObjectSets = map[string]string{
	"CellInformationList":                        "CellInformation-ItemIEs",
	"CellMeasurementResultEUTRAENDCList":         "CellMeasurementResult-E-UTRA-ENDC-ItemIEs",
	"CellMeasurementResultList":                  "CellMeasurementResult-ItemIEs",
	"CellMeasurementResultNRENDCList":            "CellMeasurementResult-NR-ENDC-ItemIEs",
	"CellToReportEUTRAENDCList":                  "CellToReport-E-UTRA-ENDC-Item-IEs",
	"CellToReportList":                           "CellToReport-ItemIEs",
	"CellToReportNRENDCList":                     "CellToReport-NR-ENDC-ItemIEs",
	"CompleteFailureCauseInformationList":        "CompleteFailureCauseInformation-ItemIEs",
	"ERABList":                                   "E-RAB-ItemIEs",
	"ERABUsageReportList":                        "E-RABUsageReport-ItemIEs",
	"ERABsAdmittedList":                          "E-RABs-Admitted-ItemIEs",
	"ERABsAdmittedToBeAddedList":                 "E-RABs-Admitted-ToBeAdded-ItemIEs",
	"ERABsAdmittedToBeAddedModAckList":           "E-RABs-Admitted-ToBeAdded-ModAckItemIEs",
	"ERABsAdmittedToBeAddedSgNBAddReqAckList":    "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-ItemIEs",
	"ERABsAdmittedToBeAddedSgNBModAckList":       "E-RABs-Admitted-ToBeAdded-SgNBModAck-ItemIEs",
	"ERABsAdmittedToBeModifiedModAckList":        "E-RABs-Admitted-ToBeModified-ModAckItemIEs",
	"ERABsAdmittedToBeModifiedSgNBModAckList":    "E-RABs-Admitted-ToBeModified-SgNBModAck-ItemIEs",
	"ERABsAdmittedToBeModifiedSgNBModConfList":   "E-RABs-AdmittedToBeModified-SgNBModConf-ItemIEs",
	"ERABsAdmittedToBeReleasedModAckList":        "E-RABs-Admitted-ToBeReleased-ModAckItemIEs",
	"ERABsAdmittedToBeReleasedSgNBModAckList":    "E-RABs-Admitted-ToBeReleased-SgNBModAck-ItemIEs",
	"ERABsAdmittedToBeReleasedSgNBRelReqAckList": "E-RABs-Admitted-ToBeReleased-SgNBRelReqAck-ItemIEs",
	"ERABsDataForwardingAddressList":             "E-RABs-DataForwardingAddress-ItemIEs",
	"ERABsSubjectToCounterCheckList":             "E-RABs-SubjectToCounterCheckItemIEs",
	"ERABsSubjectToSgNBCounterCheckList":         "E-RABs-SubjectToSgNBCounterCheck-ItemIEs",
	"ERABsSubjectToStatusTransferList":           "E-RABs-SubjectToStatusTransfer-ItemIEs",
	"ERABsToBeAddedList":                         "E-RABs-ToBeAdded-ItemIEs",
	"ERABsToBeAddedListModReq":                   "E-RABs-ToBeAdded-ModReqItemIEs",
	"ERABsToBeAddedSgNBAddReqList":               "E-RABs-ToBeAdded-SgNBAddReq-ItemIEs",
	"ERABsToBeAddedSgNBModReqList":               "E-RABs-ToBeAdded-SgNBModReq-ItemIEs",
	"ERABsToBeModifiedListModReq":                "E-RABs-ToBeModified-ModReqItemIEs",
	"ERABsToBeModifiedSgNBModReqList":            "E-RABs-ToBeModified-SgNBModReq-ItemIEs",
	"ERABsToBeModifiedSgNBModReqdList":           "E-RABs-ToBeModified-SgNBModReqd-ItemIEs",
	"ERABsToBeReleasedListModReq":                "E-RABs-ToBeReleased-ModReqItemIEs",
	"ERABsToBeReleasedListRelConf":               "E-RABs-ToBeReleased-RelConfItemIEs",
	"ERABsToBeReleasedListRelReq":                "E-RABs-ToBeReleased-RelReqItemIEs",
	"ERABsToBeReleasedModReqd":                   "E-RABs-ToBeReleased-ModReqdItemIEs",
	"ERABsToBeReleasedSgNBChaConfList":           "E-RABs-ToBeReleased-SgNBChaConf-ItemIEs",
	"ERABsToBeReleasedSgNBModReqList":            "E-RABs-ToBeReleased-SgNBModReq-ItemIEs",
	"ERABsToBeReleasedSgNBModReqdList":           "E-RABs-ToBeReleased-SgNBModReqd-ItemIEs",
	"ERABsToBeReleasedSgNBRelConfList":           "E-RABs-ToBeReleased-SgNBRelConf-ItemIEs",
	"ERABsToBeReleasedSgNBRelReqList":            "E-RABs-ToBeReleased-SgNBRelReq-ItemIEs",
	"ERABsToBeReleasedSgNBRelReqdList":           "E-RABs-ToBeReleased-SgNBRelReqd-ItemIEs",
	"ERABsToBeSetupList":                         "E-RABs-ToBeSetup-ItemIEs",
	"ERABsToBeSetupListRetrieve":                 "E-RABs-ToBeSetupRetrieve-ItemIEs",
	"MeasurementFailureCauseList":                "MeasurementFailureCause-ItemIEs",
	"MeasurementInitiationResultList":            "MeasurementInitiationResult-ItemIEs",
	"SecondaryRATUsageReportList":                "SecondaryRATUsageReport-ItemIEs",
}

var protocolExtensionFieldObjectSets = map[string]string{
	"CHOinformationREQ.IEExtensions":                                          "CHOinformation-REQ-ExtIEs",
	"CellInformationItem.IEExtensions":                                        "CellInformation-Item-ExtIEs",
	"CellMeasurementResultItem.IEExtensions":                                  "CellMeasurementResult-Item-ExtIEs",
	"ERABLevelQoSParameters.IEExtensions":                                     "E-RAB-Level-QoS-Parameters-ExtIEs",
	"ERABsAdmittedItem.IEExtensions":                                          "E-RABs-Admitted-Item-ExtIEs",
	"ERABsAdmittedToBeAddedItemSCGBearer.IEExtensions":                        "E-RABs-Admitted-ToBeAdded-Item-SCG-BearerExtIEs",
	"ERABsAdmittedToBeAddedItemSplitBearer.IEExtensions":                      "E-RABs-Admitted-ToBeAdded-Item-Split-BearerExtIEs",
	"ERABsAdmittedToBeAddedModAckItemSCGBearer.IEExtensions":                  "E-RABs-Admitted-ToBeAdded-ModAckItem-SCG-BearerExtIEs",
	"ERABsAdmittedToBeAddedModAckItemSplitBearer.IEExtensions":                "E-RABs-Admitted-ToBeAdded-ModAckItem-Split-BearerExtIEs",
	"ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPnotpresent.IEExtensions":  "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPpresent.IEExtensions":     "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item-SgNBPDCPpresentExtIEs",
	"ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPnotpresent.IEExtensions":     "E-RABs-Admitted-ToBeAdded-SgNBModAck-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPpresent.IEExtensions":        "E-RABs-Admitted-ToBeAdded-SgNBModAck-Item-SgNBPDCPpresentExtIEs",
	"ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPnotpresent.IEExtensions":  "E-RABs-Admitted-ToBeModified-SgNBModAck-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPpresent.IEExtensions":     "E-RABs-Admitted-ToBeModified-SgNBModAck-Item-SgNBPDCPpresentExtIEs",
	"ERABsAdmittedToBeModifiedSgNBModConfItemSgNBPDCPnotpresent.IEExtensions": "E-RABs-AdmittedToBeModified-SgNBModConf-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsSubjectToStatusTransferItem.IEExtensions":                           "E-RABs-SubjectToStatusTransfer-ItemExtIEs",
	"ERABsToBeAddedItemSCGBearer.IEExtensions":                                "E-RABs-ToBeAdded-Item-SCG-BearerExtIEs",
	"ERABsToBeAddedItemSplitBearer.IEExtensions":                              "E-RABs-ToBeAdded-Item-Split-BearerExtIEs",
	"ERABsToBeAddedModReqItemSCGBearer.IEExtensions":                          "E-RABs-ToBeAdded-ModReqItem-SCG-BearerExtIEs",
	"ERABsToBeAddedModReqItemSplitBearer.IEExtensions":                        "E-RABs-ToBeAdded-ModReqItem-Split-BearerExtIEs",
	"ERABsToBeAddedSgNBAddReqItemSgNBPDCPnotpresent.IEExtensions":             "E-RABs-ToBeAdded-SgNBAddReq-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsToBeAddedSgNBAddReqItemSgNBPDCPpresent.IEExtensions":                "E-RABs-ToBeAdded-SgNBAddReq-Item-SgNBPDCPpresentExtIEs",
	"ERABsToBeAddedSgNBModReqItemSgNBPDCPnotpresent.IEExtensions":             "E-RABs-ToBeAdded-SgNBModReq-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsToBeAddedSgNBModReqItemSgNBPDCPpresent.IEExtensions":                "E-RABs-ToBeAdded-SgNBModReq-Item-SgNBPDCPpresentExtIEs",
	"ERABsToBeModifiedSgNBModReqItemSgNBPDCPnotpresent.IEExtensions":          "E-RABs-ToBeModified-SgNBModReq-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsToBeModifiedSgNBModReqItemSgNBPDCPpresent.IEExtensions":             "E-RABs-ToBeModified-SgNBModReq-Item-SgNBPDCPpresentExtIEs",
	"ERABsToBeModifiedSgNBModReqdItemSgNBPDCPnotpresent.IEExtensions":         "E-RABs-ToBeModified-SgNBModReqd-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsToBeModifiedSgNBModReqdItemSgNBPDCPpresent.IEExtensions":            "E-RABs-ToBeModified-SgNBModReqd-Item-SgNBPDCPpresentExtIEs",
	"ERABsToBeReleasedSgNBChaConfItemSgNBPDCPpresent.IEExtensions":            "E-RABs-ToBeReleased-SgNBChaConf-Item-SgNBPDCPpresentExtIEs",
	"ERABsToBeReleasedSgNBModReqdItem.IEExtensions":                           "E-RABs-ToBeReleased-SgNBModReqd-ItemExtIEs",
	"ERABsToBeSetupItem.IEExtensions":                                         "E-RABs-ToBeSetup-ItemExtIEs",
	"ERABsToBeSetupRetrieveItem.IEExtensions":                                 "E-RABs-ToBeSetupRetrieve-ItemExtIEs",
	"FDDInfo.IEExtensions":                                                    "FDD-Info-ExtIEs",
	"FDDInfoNeighbourServedNRCellInformation.IEExtensions":                    "FDD-InfoNeighbourServedNRCell-Information-ExtIEs",
	"FDDInfoServedNRCellInformation.IEExtensions":                             "FDD-InfoServedNRCell-Information-ExtIEs",
	"GBRQosInformation.IEExtensions":                                          "GBR-QosInformation-ExtIEs",
	"GTPtunnelEndpoint.IEExtensions":                                          "GTPtunnelEndpoint-ExtIEs",
	"HandoverRestrictionList.IEExtensions":                                    "HandoverRestrictionList-ExtIEs",
	"LastVisitedEUTRANCellInformation.IEExtensions":                           "LastVisitedEUTRANCellInformation-ExtIEs",
	"LocationReportingInformation.IEExtensions":                               "LocationReportingInformation-ExtIEs",
	"M4Configuration.IEExtensions":                                            "M4Configuration-ExtIEs",
	"M5Configuration.IEExtensions":                                            "M5Configuration-ExtIEs",
	"M6Configuration.IEExtensions":                                            "M6Configuration-ExtIEs",
	"M7Configuration.IEExtensions":                                            "M7Configuration-ExtIEs",
	"MDTConfiguration.IEExtensions":                                           "MDT-Configuration-ExtIEs",
	"MeNBResourceCoordinationInformation.IEExtensions":                        "MeNBResourceCoordinationInformationExtIEs",
	"NRFreqInfo.IEExtensions":                                                 "NRFreqInfo-ExtIEs",
	"NRRAReportListItem.IEExtensions":                                         "NRRAReportList-Item-ExtIEs",
	"NRRadioResourceStatus.IEExtensions":                                      "NRRadioResourceStatus-ExtIEs",
	"ProSeAuthorized.IEExtensions":                                            "ProSeAuthorized-ExtIEs",
	"RadioResourceStatus.IEExtensions":                                        "RadioResourceStatus-ExtIEs",
	"RelativeNarrowbandTxPower.IEExtensions":                                  "RelativeNarrowbandTxPower-ExtIEs",
	"SULInformation.IEExtensions":                                             "SULInformation-ExtIEs",
	"ServedCellInformation.IEExtensions":                                      "ServedCell-Information-ExtIEs",
	"ServedCellsToModifyItem.IEExtensions":                                    "ServedCellsToModify-Item-ExtIEs",
	"ServedNRCellInformation.IEExtensions":                                    "ServedNRCell-Information-ExtIEs",
	"SgNBResourceCoordinationInformation.IEExtensions":                        "SgNBResourceCoordinationInformationExtIEs",
	"TDDInfo.IEExtensions":                                                    "TDD-Info-ExtIEs",
	"TDDInfoNeighbourServedNRCellInformation.IEExtensions":                    "TDD-InfoNeighbourServedNRCell-Information-ExtIEs",
	"TDDInfoServedNRCellInformation.IEExtensions":                             "TDD-InfoServedNRCell-Information-ExtIEs",
	"TraceActivation.IEExtensions":                                            "TraceActivation-ExtIEs",
	"UEAggregateMaximumBitRate.IEExtensions":                                  "UEAggregate-MaximumBitrate-ExtIEs",
	"UEAppLayerMeasConfig.IEExtensions":                                       "UEAppLayerMeasConfig-ExtIEs",
	"UEContextInformation.IEExtensions":                                       "UE-ContextInformation-ExtIEs",
	"UEContextInformationRetrieve.IEExtensions":                               "UE-ContextInformationRetrieve-ExtIEs",
	"UEContextInformationSgNBModReq.IEExtensions":                             "UE-ContextInformationSgNBModReqExtIEs",
}

var protocolExtensionTypeObjectSets = map[string]string{}

func protocolIEObjectSet(context string) string {
	switch context {
	case "AccessAndMobilityIndication":
		return "AccessAndMobilityIndication-IEs"
	case "AccessAndMobilityIndication-IEs":
		return "AccessAndMobilityIndication-IEs"
	case "CPC-cancel-IEs":
		return "CPC-cancel-IEs"
	case "CPCCancel":
		return "CPC-cancel-IEs"
	case "CellActivationFailure":
		return "CellActivationFailure-IEs"
	case "CellActivationFailure-IEs":
		return "CellActivationFailure-IEs"
	case "CellActivationRequest":
		return "CellActivationRequest-IEs"
	case "CellActivationRequest-IEs":
		return "CellActivationRequest-IEs"
	case "CellActivationResponse":
		return "CellActivationResponse-IEs"
	case "CellActivationResponse-IEs":
		return "CellActivationResponse-IEs"
	case "CellInformation-ItemIEs":
		return "CellInformation-ItemIEs"
	case "CellInformationItem":
		return "CellInformation-ItemIEs"
	case "CellMeasurementResult-E-UTRA-ENDC-ItemIEs":
		return "CellMeasurementResult-E-UTRA-ENDC-ItemIEs"
	case "CellMeasurementResult-ItemIEs":
		return "CellMeasurementResult-ItemIEs"
	case "CellMeasurementResult-NR-ENDC-ItemIEs":
		return "CellMeasurementResult-NR-ENDC-ItemIEs"
	case "CellMeasurementResultEUTRAENDCItem":
		return "CellMeasurementResult-E-UTRA-ENDC-ItemIEs"
	case "CellMeasurementResultItem":
		return "CellMeasurementResult-ItemIEs"
	case "CellMeasurementResultNRENDCItem":
		return "CellMeasurementResult-NR-ENDC-ItemIEs"
	case "CellToReport-E-UTRA-ENDC-Item-IEs":
		return "CellToReport-E-UTRA-ENDC-Item-IEs"
	case "CellToReport-ItemIEs":
		return "CellToReport-ItemIEs"
	case "CellToReport-NR-ENDC-ItemIEs":
		return "CellToReport-NR-ENDC-ItemIEs"
	case "CellToReportEUTRAENDCItem":
		return "CellToReport-E-UTRA-ENDC-Item-IEs"
	case "CellToReportItem":
		return "CellToReport-ItemIEs"
	case "CellToReportNRENDCItem":
		return "CellToReport-NR-ENDC-ItemIEs"
	case "CellTrafficTrace":
		return "CellTrafficTraceIEs"
	case "CellTrafficTraceIEs":
		return "CellTrafficTraceIEs"
	case "CompleteFailureCauseInformation-ItemIEs":
		return "CompleteFailureCauseInformation-ItemIEs"
	case "CompleteFailureCauseInformationItem":
		return "CompleteFailureCauseInformation-ItemIEs"
	case "ConditionalHandoverCancel":
		return "ConditionalHandoverCancel-IEs"
	case "ConditionalHandoverCancel-IEs":
		return "ConditionalHandoverCancel-IEs"
	case "DataForwardingAddressIndication":
		return "DataForwardingAddressIndication-IEs"
	case "DataForwardingAddressIndication-IEs":
		return "DataForwardingAddressIndication-IEs"
	case "DeactivateTrace":
		return "DeactivateTraceIEs"
	case "DeactivateTraceIEs":
		return "DeactivateTraceIEs"
	case "E-RAB-ItemIEs":
		return "E-RAB-ItemIEs"
	case "E-RABUsageReport-ItemIEs":
		return "E-RABUsageReport-ItemIEs"
	case "E-RABs-Admitted-ItemIEs":
		return "E-RABs-Admitted-ItemIEs"
	case "E-RABs-Admitted-ToBeAdded-ItemIEs":
		return "E-RABs-Admitted-ToBeAdded-ItemIEs"
	case "E-RABs-Admitted-ToBeAdded-ModAckItemIEs":
		return "E-RABs-Admitted-ToBeAdded-ModAckItemIEs"
	case "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-ItemIEs":
		return "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-ItemIEs"
	case "E-RABs-Admitted-ToBeAdded-SgNBModAck-ItemIEs":
		return "E-RABs-Admitted-ToBeAdded-SgNBModAck-ItemIEs"
	case "E-RABs-Admitted-ToBeModified-ModAckItemIEs":
		return "E-RABs-Admitted-ToBeModified-ModAckItemIEs"
	case "E-RABs-Admitted-ToBeModified-SgNBModAck-ItemIEs":
		return "E-RABs-Admitted-ToBeModified-SgNBModAck-ItemIEs"
	case "E-RABs-Admitted-ToBeReleased-ModAckItemIEs":
		return "E-RABs-Admitted-ToBeReleased-ModAckItemIEs"
	case "E-RABs-Admitted-ToBeReleased-SgNBModAck-ItemIEs":
		return "E-RABs-Admitted-ToBeReleased-SgNBModAck-ItemIEs"
	case "E-RABs-Admitted-ToBeReleased-SgNBRelReqAck-ItemIEs":
		return "E-RABs-Admitted-ToBeReleased-SgNBRelReqAck-ItemIEs"
	case "E-RABs-AdmittedToBeModified-SgNBModConf-ItemIEs":
		return "E-RABs-AdmittedToBeModified-SgNBModConf-ItemIEs"
	case "E-RABs-DataForwardingAddress-ItemIEs":
		return "E-RABs-DataForwardingAddress-ItemIEs"
	case "E-RABs-SubjectToCounterCheckItemIEs":
		return "E-RABs-SubjectToCounterCheckItemIEs"
	case "E-RABs-SubjectToSgNBCounterCheck-ItemIEs":
		return "E-RABs-SubjectToSgNBCounterCheck-ItemIEs"
	case "E-RABs-SubjectToStatusTransfer-ItemIEs":
		return "E-RABs-SubjectToStatusTransfer-ItemIEs"
	case "E-RABs-ToBeAdded-ItemIEs":
		return "E-RABs-ToBeAdded-ItemIEs"
	case "E-RABs-ToBeAdded-ModReqItemIEs":
		return "E-RABs-ToBeAdded-ModReqItemIEs"
	case "E-RABs-ToBeAdded-SgNBAddReq-ItemIEs":
		return "E-RABs-ToBeAdded-SgNBAddReq-ItemIEs"
	case "E-RABs-ToBeAdded-SgNBModReq-ItemIEs":
		return "E-RABs-ToBeAdded-SgNBModReq-ItemIEs"
	case "E-RABs-ToBeModified-ModReqItemIEs":
		return "E-RABs-ToBeModified-ModReqItemIEs"
	case "E-RABs-ToBeModified-SgNBModReq-ItemIEs":
		return "E-RABs-ToBeModified-SgNBModReq-ItemIEs"
	case "E-RABs-ToBeModified-SgNBModReqd-ItemIEs":
		return "E-RABs-ToBeModified-SgNBModReqd-ItemIEs"
	case "E-RABs-ToBeReleased-ModReqItemIEs":
		return "E-RABs-ToBeReleased-ModReqItemIEs"
	case "E-RABs-ToBeReleased-ModReqdItemIEs":
		return "E-RABs-ToBeReleased-ModReqdItemIEs"
	case "E-RABs-ToBeReleased-RelConfItemIEs":
		return "E-RABs-ToBeReleased-RelConfItemIEs"
	case "E-RABs-ToBeReleased-RelReqItemIEs":
		return "E-RABs-ToBeReleased-RelReqItemIEs"
	case "E-RABs-ToBeReleased-SgNBChaConf-ItemIEs":
		return "E-RABs-ToBeReleased-SgNBChaConf-ItemIEs"
	case "E-RABs-ToBeReleased-SgNBModReq-ItemIEs":
		return "E-RABs-ToBeReleased-SgNBModReq-ItemIEs"
	case "E-RABs-ToBeReleased-SgNBModReqd-ItemIEs":
		return "E-RABs-ToBeReleased-SgNBModReqd-ItemIEs"
	case "E-RABs-ToBeReleased-SgNBRelConf-ItemIEs":
		return "E-RABs-ToBeReleased-SgNBRelConf-ItemIEs"
	case "E-RABs-ToBeReleased-SgNBRelReq-ItemIEs":
		return "E-RABs-ToBeReleased-SgNBRelReq-ItemIEs"
	case "E-RABs-ToBeReleased-SgNBRelReqd-ItemIEs":
		return "E-RABs-ToBeReleased-SgNBRelReqd-ItemIEs"
	case "E-RABs-ToBeSetup-ItemIEs":
		return "E-RABs-ToBeSetup-ItemIEs"
	case "E-RABs-ToBeSetupRetrieve-ItemIEs":
		return "E-RABs-ToBeSetupRetrieve-ItemIEs"
	case "ENB-ENDCConfigUpdateIEs":
		return "ENB-ENDCConfigUpdateIEs"
	case "ENB-ENDCX2RemovalReqAckIEs":
		return "ENB-ENDCX2RemovalReqAckIEs"
	case "ENB-ENDCX2RemovalReqIEs":
		return "ENB-ENDCX2RemovalReqIEs"
	case "ENB-ENDCX2SetupReqAckIEs":
		return "ENB-ENDCX2SetupReqAckIEs"
	case "ENB-ENDCX2SetupReqIEs":
		return "ENB-ENDCX2SetupReqIEs"
	case "ENB-EUTRA-NRCellResourceCoordinationReqAckIEs":
		return "ENB-EUTRA-NRCellResourceCoordinationReqAckIEs"
	case "ENB-EUTRA-NRCellResourceCoordinationReqIEs":
		return "ENB-EUTRA-NRCellResourceCoordinationReqIEs"
	case "ENBConfigurationUpdate":
		return "ENBConfigurationUpdate-IEs"
	case "ENBConfigurationUpdate-IEs":
		return "ENBConfigurationUpdate-IEs"
	case "ENBConfigurationUpdateAcknowledge":
		return "ENBConfigurationUpdateAcknowledge-IEs"
	case "ENBConfigurationUpdateAcknowledge-IEs":
		return "ENBConfigurationUpdateAcknowledge-IEs"
	case "ENBConfigurationUpdateFailure":
		return "ENBConfigurationUpdateFailure-IEs"
	case "ENBConfigurationUpdateFailure-IEs":
		return "ENBConfigurationUpdateFailure-IEs"
	case "ENBENDCConfigUpdate":
		return "ENB-ENDCConfigUpdateIEs"
	case "ENBENDCX2RemovalReq":
		return "ENB-ENDCX2RemovalReqIEs"
	case "ENBENDCX2RemovalReqAck":
		return "ENB-ENDCX2RemovalReqAckIEs"
	case "ENBENDCX2SetupReq":
		return "ENB-ENDCX2SetupReqIEs"
	case "ENBENDCX2SetupReqAck":
		return "ENB-ENDCX2SetupReqAckIEs"
	case "ENBEUTRANRCellResourceCoordinationReq":
		return "ENB-EUTRA-NRCellResourceCoordinationReqIEs"
	case "ENBEUTRANRCellResourceCoordinationReqAck":
		return "ENB-EUTRA-NRCellResourceCoordinationReqAckIEs"
	case "ENDCCellActivationFailure":
		return "ENDCCellActivationFailure-IEs"
	case "ENDCCellActivationFailure-IEs":
		return "ENDCCellActivationFailure-IEs"
	case "ENDCCellActivationRequest":
		return "ENDCCellActivationRequest-IEs"
	case "ENDCCellActivationRequest-IEs":
		return "ENDCCellActivationRequest-IEs"
	case "ENDCCellActivationResponse":
		return "ENDCCellActivationResponse-IEs"
	case "ENDCCellActivationResponse-IEs":
		return "ENDCCellActivationResponse-IEs"
	case "ENDCConfigurationTransfer":
		return "ENDCConfigurationTransfer-IEs"
	case "ENDCConfigurationTransfer-IEs":
		return "ENDCConfigurationTransfer-IEs"
	case "ENDCConfigurationUpdate":
		return "ENDCConfigurationUpdate-IEs"
	case "ENDCConfigurationUpdate-IEs":
		return "ENDCConfigurationUpdate-IEs"
	case "ENDCConfigurationUpdateAcknowledge":
		return "ENDCConfigurationUpdateAcknowledge-IEs"
	case "ENDCConfigurationUpdateAcknowledge-IEs":
		return "ENDCConfigurationUpdateAcknowledge-IEs"
	case "ENDCConfigurationUpdateFailure":
		return "ENDCConfigurationUpdateFailure-IEs"
	case "ENDCConfigurationUpdateFailure-IEs":
		return "ENDCConfigurationUpdateFailure-IEs"
	case "ENDCPartialResetConfirm":
		return "ENDCPartialResetConfirm-IEs"
	case "ENDCPartialResetConfirm-IEs":
		return "ENDCPartialResetConfirm-IEs"
	case "ENDCPartialResetRequired":
		return "ENDCPartialResetRequired-IEs"
	case "ENDCPartialResetRequired-IEs":
		return "ENDCPartialResetRequired-IEs"
	case "ENDCResourceStatusFailure":
		return "ENDCResourceStatusFailure-IEs"
	case "ENDCResourceStatusFailure-IEs":
		return "ENDCResourceStatusFailure-IEs"
	case "ENDCResourceStatusRequest":
		return "ENDCResourceStatusRequest-IEs"
	case "ENDCResourceStatusRequest-IEs":
		return "ENDCResourceStatusRequest-IEs"
	case "ENDCResourceStatusResponse":
		return "ENDCResourceStatusResponse-IEs"
	case "ENDCResourceStatusResponse-IEs":
		return "ENDCResourceStatusResponse-IEs"
	case "ENDCResourceStatusUpdate":
		return "ENDCResourceStatusUpdate-IEs"
	case "ENDCResourceStatusUpdate-IEs":
		return "ENDCResourceStatusUpdate-IEs"
	case "ENDCX2RemovalFailure":
		return "ENDCX2RemovalFailure-IEs"
	case "ENDCX2RemovalFailure-IEs":
		return "ENDCX2RemovalFailure-IEs"
	case "ENDCX2RemovalRequest":
		return "ENDCX2RemovalRequest-IEs"
	case "ENDCX2RemovalRequest-IEs":
		return "ENDCX2RemovalRequest-IEs"
	case "ENDCX2RemovalResponse":
		return "ENDCX2RemovalResponse-IEs"
	case "ENDCX2RemovalResponse-IEs":
		return "ENDCX2RemovalResponse-IEs"
	case "ENDCX2SetupFailure":
		return "ENDCX2SetupFailure-IEs"
	case "ENDCX2SetupFailure-IEs":
		return "ENDCX2SetupFailure-IEs"
	case "ENDCX2SetupRequest":
		return "ENDCX2SetupRequest-IEs"
	case "ENDCX2SetupRequest-IEs":
		return "ENDCX2SetupRequest-IEs"
	case "ENDCX2SetupResponse":
		return "ENDCX2SetupResponse-IEs"
	case "ENDCX2SetupResponse-IEs":
		return "ENDCX2SetupResponse-IEs"
	case "ERABItem":
		return "E-RAB-ItemIEs"
	case "ERABUsageReportItem":
		return "E-RABUsageReport-ItemIEs"
	case "ERABsAdmittedItem":
		return "E-RABs-Admitted-ItemIEs"
	case "ERABsAdmittedToBeAddedItem":
		return "E-RABs-Admitted-ToBeAdded-ItemIEs"
	case "ERABsAdmittedToBeAddedModAckItem":
		return "E-RABs-Admitted-ToBeAdded-ModAckItemIEs"
	case "ERABsAdmittedToBeAddedSgNBAddReqAckItem":
		return "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-ItemIEs"
	case "ERABsAdmittedToBeAddedSgNBModAckItem":
		return "E-RABs-Admitted-ToBeAdded-SgNBModAck-ItemIEs"
	case "ERABsAdmittedToBeModifiedModAckItem":
		return "E-RABs-Admitted-ToBeModified-ModAckItemIEs"
	case "ERABsAdmittedToBeModifiedSgNBModAckItem":
		return "E-RABs-Admitted-ToBeModified-SgNBModAck-ItemIEs"
	case "ERABsAdmittedToBeModifiedSgNBModConfItem":
		return "E-RABs-AdmittedToBeModified-SgNBModConf-ItemIEs"
	case "ERABsAdmittedToBeReleasedModAckItem":
		return "E-RABs-Admitted-ToBeReleased-ModAckItemIEs"
	case "ERABsAdmittedToBeReleasedSgNBModAckItem":
		return "E-RABs-Admitted-ToBeReleased-SgNBModAck-ItemIEs"
	case "ERABsAdmittedToBeReleasedSgNBRelReqAckItem":
		return "E-RABs-Admitted-ToBeReleased-SgNBRelReqAck-ItemIEs"
	case "ERABsDataForwardingAddressItem":
		return "E-RABs-DataForwardingAddress-ItemIEs"
	case "ERABsSubjectToCounterCheckItem":
		return "E-RABs-SubjectToCounterCheckItemIEs"
	case "ERABsSubjectToSgNBCounterCheckItem":
		return "E-RABs-SubjectToSgNBCounterCheck-ItemIEs"
	case "ERABsSubjectToStatusTransferItem":
		return "E-RABs-SubjectToStatusTransfer-ItemIEs"
	case "ERABsToBeAddedItem":
		return "E-RABs-ToBeAdded-ItemIEs"
	case "ERABsToBeAddedModReqItem":
		return "E-RABs-ToBeAdded-ModReqItemIEs"
	case "ERABsToBeAddedSgNBAddReqItem":
		return "E-RABs-ToBeAdded-SgNBAddReq-ItemIEs"
	case "ERABsToBeAddedSgNBModReqItem":
		return "E-RABs-ToBeAdded-SgNBModReq-ItemIEs"
	case "ERABsToBeModifiedModReqItem":
		return "E-RABs-ToBeModified-ModReqItemIEs"
	case "ERABsToBeModifiedSgNBModReqItem":
		return "E-RABs-ToBeModified-SgNBModReq-ItemIEs"
	case "ERABsToBeModifiedSgNBModReqdItem":
		return "E-RABs-ToBeModified-SgNBModReqd-ItemIEs"
	case "ERABsToBeReleasedModReqItem":
		return "E-RABs-ToBeReleased-ModReqItemIEs"
	case "ERABsToBeReleasedModReqdItem":
		return "E-RABs-ToBeReleased-ModReqdItemIEs"
	case "ERABsToBeReleasedRelConfItem":
		return "E-RABs-ToBeReleased-RelConfItemIEs"
	case "ERABsToBeReleasedRelReqItem":
		return "E-RABs-ToBeReleased-RelReqItemIEs"
	case "ERABsToBeReleasedSgNBChaConfItem":
		return "E-RABs-ToBeReleased-SgNBChaConf-ItemIEs"
	case "ERABsToBeReleasedSgNBModReqItem":
		return "E-RABs-ToBeReleased-SgNBModReq-ItemIEs"
	case "ERABsToBeReleasedSgNBModReqdItem":
		return "E-RABs-ToBeReleased-SgNBModReqd-ItemIEs"
	case "ERABsToBeReleasedSgNBRelConfItem":
		return "E-RABs-ToBeReleased-SgNBRelConf-ItemIEs"
	case "ERABsToBeReleasedSgNBRelReqItem":
		return "E-RABs-ToBeReleased-SgNBRelReq-ItemIEs"
	case "ERABsToBeReleasedSgNBRelReqdItem":
		return "E-RABs-ToBeReleased-SgNBRelReqd-ItemIEs"
	case "ERABsToBeSetupItem":
		return "E-RABs-ToBeSetup-ItemIEs"
	case "ERABsToBeSetupRetrieveItem":
		return "E-RABs-ToBeSetupRetrieve-ItemIEs"
	case "EUTRANRCellResourceCoordinationRequest":
		return "EUTRANRCellResourceCoordinationRequest-IEs"
	case "EUTRANRCellResourceCoordinationRequest-IEs":
		return "EUTRANRCellResourceCoordinationRequest-IEs"
	case "EUTRANRCellResourceCoordinationResponse":
		return "EUTRANRCellResourceCoordinationResponse-IEs"
	case "EUTRANRCellResourceCoordinationResponse-IEs":
		return "EUTRANRCellResourceCoordinationResponse-IEs"
	case "EarlyStatusTransfer":
		return "EarlyStatusTransfer-IEs"
	case "EarlyStatusTransfer-IEs":
		return "EarlyStatusTransfer-IEs"
	case "En-gNB-ENDCConfigUpdateAckIEs":
		return "En-gNB-ENDCConfigUpdateAckIEs"
	case "En-gNB-ENDCConfigUpdateIEs":
		return "En-gNB-ENDCConfigUpdateIEs"
	case "En-gNB-ENDCX2RemovalReqAckIEs":
		return "En-gNB-ENDCX2RemovalReqAckIEs"
	case "En-gNB-ENDCX2RemovalReqIEs":
		return "En-gNB-ENDCX2RemovalReqIEs"
	case "En-gNB-ENDCX2SetupReqAckIEs":
		return "En-gNB-ENDCX2SetupReqAckIEs"
	case "En-gNB-ENDCX2SetupReqIEs":
		return "En-gNB-ENDCX2SetupReqIEs"
	case "En-gNB-EUTRA-NRCellResourceCoordinationReqAckIEs":
		return "En-gNB-EUTRA-NRCellResourceCoordinationReqAckIEs"
	case "En-gNB-EUTRA-NRCellResourceCoordinationReqIEs":
		return "En-gNB-EUTRA-NRCellResourceCoordinationReqIEs"
	case "EnGNBENDCConfigUpdate":
		return "En-gNB-ENDCConfigUpdateIEs"
	case "EnGNBENDCConfigUpdateAck":
		return "En-gNB-ENDCConfigUpdateAckIEs"
	case "EnGNBENDCX2RemovalReq":
		return "En-gNB-ENDCX2RemovalReqIEs"
	case "EnGNBENDCX2RemovalReqAck":
		return "En-gNB-ENDCX2RemovalReqAckIEs"
	case "EnGNBENDCX2SetupReq":
		return "En-gNB-ENDCX2SetupReqIEs"
	case "EnGNBENDCX2SetupReqAck":
		return "En-gNB-ENDCX2SetupReqAckIEs"
	case "EnGNBEUTRANRCellResourceCoordinationReq":
		return "En-gNB-EUTRA-NRCellResourceCoordinationReqIEs"
	case "EnGNBEUTRANRCellResourceCoordinationReqAck":
		return "En-gNB-EUTRA-NRCellResourceCoordinationReqAckIEs"
	case "ErrorIndication":
		return "ErrorIndication-IEs"
	case "ErrorIndication-IEs":
		return "ErrorIndication-IEs"
	case "F1CTrafficTransfer":
		return "F1CTrafficTransfer-IEs"
	case "F1CTrafficTransfer-IEs":
		return "F1CTrafficTransfer-IEs"
	case "GNBStatusIndication":
		return "GNBStatusIndicationIEs"
	case "GNBStatusIndicationIEs":
		return "GNBStatusIndicationIEs"
	case "HandoverCancel":
		return "HandoverCancel-IEs"
	case "HandoverCancel-IEs":
		return "HandoverCancel-IEs"
	case "HandoverPreparationFailure":
		return "HandoverPreparationFailure-IEs"
	case "HandoverPreparationFailure-IEs":
		return "HandoverPreparationFailure-IEs"
	case "HandoverReport":
		return "HandoverReport-IEs"
	case "HandoverReport-IEs":
		return "HandoverReport-IEs"
	case "HandoverRequest":
		return "HandoverRequest-IEs"
	case "HandoverRequest-IEs":
		return "HandoverRequest-IEs"
	case "HandoverRequestAcknowledge":
		return "HandoverRequestAcknowledge-IEs"
	case "HandoverRequestAcknowledge-IEs":
		return "HandoverRequestAcknowledge-IEs"
	case "HandoverSuccess":
		return "HandoverSuccess-IEs"
	case "HandoverSuccess-IEs":
		return "HandoverSuccess-IEs"
	case "LoadInformation":
		return "LoadInformation-IEs"
	case "LoadInformation-IEs":
		return "LoadInformation-IEs"
	case "MeasurementFailureCause-ItemIEs":
		return "MeasurementFailureCause-ItemIEs"
	case "MeasurementFailureCauseItem":
		return "MeasurementFailureCause-ItemIEs"
	case "MeasurementInitiationResult-ItemIEs":
		return "MeasurementInitiationResult-ItemIEs"
	case "MeasurementInitiationResultItem":
		return "MeasurementInitiationResult-ItemIEs"
	case "MobilityChangeAcknowledge":
		return "MobilityChangeAcknowledge-IEs"
	case "MobilityChangeAcknowledge-IEs":
		return "MobilityChangeAcknowledge-IEs"
	case "MobilityChangeFailure":
		return "MobilityChangeFailure-IEs"
	case "MobilityChangeFailure-IEs":
		return "MobilityChangeFailure-IEs"
	case "MobilityChangeRequest":
		return "MobilityChangeRequest-IEs"
	case "MobilityChangeRequest-IEs":
		return "MobilityChangeRequest-IEs"
	case "RLFIndication":
		return "RLFIndication-IEs"
	case "RLFIndication-IEs":
		return "RLFIndication-IEs"
	case "RRCTransfer":
		return "RRCTransfer-IEs"
	case "RRCTransfer-IEs":
		return "RRCTransfer-IEs"
	case "RachIndication":
		return "RachIndication-IEs"
	case "RachIndication-IEs":
		return "RachIndication-IEs"
	case "ResetRequest":
		return "ResetRequest-IEs"
	case "ResetRequest-IEs":
		return "ResetRequest-IEs"
	case "ResetResponse":
		return "ResetResponse-IEs"
	case "ResetResponse-IEs":
		return "ResetResponse-IEs"
	case "ResourceStatusFailure":
		return "ResourceStatusFailure-IEs"
	case "ResourceStatusFailure-IEs":
		return "ResourceStatusFailure-IEs"
	case "ResourceStatusRequest":
		return "ResourceStatusRequest-IEs"
	case "ResourceStatusRequest-IEs":
		return "ResourceStatusRequest-IEs"
	case "ResourceStatusResponse":
		return "ResourceStatusResponse-IEs"
	case "ResourceStatusResponse-IEs":
		return "ResourceStatusResponse-IEs"
	case "ResourceStatusUpdate":
		return "ResourceStatusUpdate-IEs"
	case "ResourceStatusUpdate-IEs":
		return "ResourceStatusUpdate-IEs"
	case "RetrieveUEContextFailure":
		return "RetrieveUEContextFailure-IEs"
	case "RetrieveUEContextFailure-IEs":
		return "RetrieveUEContextFailure-IEs"
	case "RetrieveUEContextRequest":
		return "RetrieveUEContextRequest-IEs"
	case "RetrieveUEContextRequest-IEs":
		return "RetrieveUEContextRequest-IEs"
	case "RetrieveUEContextResponse":
		return "RetrieveUEContextResponse-IEs"
	case "RetrieveUEContextResponse-IEs":
		return "RetrieveUEContextResponse-IEs"
	case "SCGFailureInformationReport":
		return "SCGFailureInformationReport-IEs"
	case "SCGFailureInformationReport-IEs":
		return "SCGFailureInformationReport-IEs"
	case "SCGFailureTransfer":
		return "SCGFailureTransfer-IEs"
	case "SCGFailureTransfer-IEs":
		return "SCGFailureTransfer-IEs"
	case "SNStatusTransfer":
		return "SNStatusTransfer-IEs"
	case "SNStatusTransfer-IEs":
		return "SNStatusTransfer-IEs"
	case "SeNBAdditionRequest":
		return "SeNBAdditionRequest-IEs"
	case "SeNBAdditionRequest-IEs":
		return "SeNBAdditionRequest-IEs"
	case "SeNBAdditionRequestAcknowledge":
		return "SeNBAdditionRequestAcknowledge-IEs"
	case "SeNBAdditionRequestAcknowledge-IEs":
		return "SeNBAdditionRequestAcknowledge-IEs"
	case "SeNBAdditionRequestReject":
		return "SeNBAdditionRequestReject-IEs"
	case "SeNBAdditionRequestReject-IEs":
		return "SeNBAdditionRequestReject-IEs"
	case "SeNBCounterCheckRequest":
		return "SeNBCounterCheckRequest-IEs"
	case "SeNBCounterCheckRequest-IEs":
		return "SeNBCounterCheckRequest-IEs"
	case "SeNBModificationConfirm":
		return "SeNBModificationConfirm-IEs"
	case "SeNBModificationConfirm-IEs":
		return "SeNBModificationConfirm-IEs"
	case "SeNBModificationRefuse":
		return "SeNBModificationRefuse-IEs"
	case "SeNBModificationRefuse-IEs":
		return "SeNBModificationRefuse-IEs"
	case "SeNBModificationRequest":
		return "SeNBModificationRequest-IEs"
	case "SeNBModificationRequest-IEs":
		return "SeNBModificationRequest-IEs"
	case "SeNBModificationRequestAcknowledge":
		return "SeNBModificationRequestAcknowledge-IEs"
	case "SeNBModificationRequestAcknowledge-IEs":
		return "SeNBModificationRequestAcknowledge-IEs"
	case "SeNBModificationRequestReject":
		return "SeNBModificationRequestReject-IEs"
	case "SeNBModificationRequestReject-IEs":
		return "SeNBModificationRequestReject-IEs"
	case "SeNBModificationRequired":
		return "SeNBModificationRequired-IEs"
	case "SeNBModificationRequired-IEs":
		return "SeNBModificationRequired-IEs"
	case "SeNBReconfigurationComplete":
		return "SeNBReconfigurationComplete-IEs"
	case "SeNBReconfigurationComplete-IEs":
		return "SeNBReconfigurationComplete-IEs"
	case "SeNBReleaseConfirm":
		return "SeNBReleaseConfirm-IEs"
	case "SeNBReleaseConfirm-IEs":
		return "SeNBReleaseConfirm-IEs"
	case "SeNBReleaseRequest":
		return "SeNBReleaseRequest-IEs"
	case "SeNBReleaseRequest-IEs":
		return "SeNBReleaseRequest-IEs"
	case "SeNBReleaseRequired":
		return "SeNBReleaseRequired-IEs"
	case "SeNBReleaseRequired-IEs":
		return "SeNBReleaseRequired-IEs"
	case "SecondaryRATDataUsageReport":
		return "SecondaryRATDataUsageReport-IEs"
	case "SecondaryRATDataUsageReport-IEs":
		return "SecondaryRATDataUsageReport-IEs"
	case "SecondaryRATUsageReport-ItemIEs":
		return "SecondaryRATUsageReport-ItemIEs"
	case "SecondaryRATUsageReportItem":
		return "SecondaryRATUsageReport-ItemIEs"
	case "SgNBActivityNotification":
		return "SgNBActivityNotification-IEs"
	case "SgNBActivityNotification-IEs":
		return "SgNBActivityNotification-IEs"
	case "SgNBAdditionRequest":
		return "SgNBAdditionRequest-IEs"
	case "SgNBAdditionRequest-IEs":
		return "SgNBAdditionRequest-IEs"
	case "SgNBAdditionRequestAcknowledge":
		return "SgNBAdditionRequestAcknowledge-IEs"
	case "SgNBAdditionRequestAcknowledge-IEs":
		return "SgNBAdditionRequestAcknowledge-IEs"
	case "SgNBAdditionRequestReject":
		return "SgNBAdditionRequestReject-IEs"
	case "SgNBAdditionRequestReject-IEs":
		return "SgNBAdditionRequestReject-IEs"
	case "SgNBChangeConfirm":
		return "SgNBChangeConfirm-IEs"
	case "SgNBChangeConfirm-IEs":
		return "SgNBChangeConfirm-IEs"
	case "SgNBChangeRefuse":
		return "SgNBChangeRefuse-IEs"
	case "SgNBChangeRefuse-IEs":
		return "SgNBChangeRefuse-IEs"
	case "SgNBChangeRequired":
		return "SgNBChangeRequired-IEs"
	case "SgNBChangeRequired-IEs":
		return "SgNBChangeRequired-IEs"
	case "SgNBCounterCheckRequest":
		return "SgNBCounterCheckRequest-IEs"
	case "SgNBCounterCheckRequest-IEs":
		return "SgNBCounterCheckRequest-IEs"
	case "SgNBModificationConfirm":
		return "SgNBModificationConfirm-IEs"
	case "SgNBModificationConfirm-IEs":
		return "SgNBModificationConfirm-IEs"
	case "SgNBModificationRefuse":
		return "SgNBModificationRefuse-IEs"
	case "SgNBModificationRefuse-IEs":
		return "SgNBModificationRefuse-IEs"
	case "SgNBModificationRequest":
		return "SgNBModificationRequest-IEs"
	case "SgNBModificationRequest-IEs":
		return "SgNBModificationRequest-IEs"
	case "SgNBModificationRequestAcknowledge":
		return "SgNBModificationRequestAcknowledge-IEs"
	case "SgNBModificationRequestAcknowledge-IEs":
		return "SgNBModificationRequestAcknowledge-IEs"
	case "SgNBModificationRequestReject":
		return "SgNBModificationRequestReject-IEs"
	case "SgNBModificationRequestReject-IEs":
		return "SgNBModificationRequestReject-IEs"
	case "SgNBModificationRequired":
		return "SgNBModificationRequired-IEs"
	case "SgNBModificationRequired-IEs":
		return "SgNBModificationRequired-IEs"
	case "SgNBReconfigurationComplete":
		return "SgNBReconfigurationComplete-IEs"
	case "SgNBReconfigurationComplete-IEs":
		return "SgNBReconfigurationComplete-IEs"
	case "SgNBReleaseConfirm":
		return "SgNBReleaseConfirm-IEs"
	case "SgNBReleaseConfirm-IEs":
		return "SgNBReleaseConfirm-IEs"
	case "SgNBReleaseRequest":
		return "SgNBReleaseRequest-IEs"
	case "SgNBReleaseRequest-IEs":
		return "SgNBReleaseRequest-IEs"
	case "SgNBReleaseRequestAcknowledge":
		return "SgNBReleaseRequestAcknowledge-IEs"
	case "SgNBReleaseRequestAcknowledge-IEs":
		return "SgNBReleaseRequestAcknowledge-IEs"
	case "SgNBReleaseRequestReject":
		return "SgNBReleaseRequestReject-IEs"
	case "SgNBReleaseRequestReject-IEs":
		return "SgNBReleaseRequestReject-IEs"
	case "SgNBReleaseRequired":
		return "SgNBReleaseRequired-IEs"
	case "SgNBReleaseRequired-IEs":
		return "SgNBReleaseRequired-IEs"
	case "TraceStart":
		return "TraceStartIEs"
	case "TraceStartIEs":
		return "TraceStartIEs"
	case "UEContextRelease":
		return "UEContextRelease-IEs"
	case "UEContextRelease-IEs":
		return "UEContextRelease-IEs"
	case "UERadioCapabilityIDMappingRequest":
		return "UERadioCapabilityIDMappingRequestIEs"
	case "UERadioCapabilityIDMappingRequestIEs":
		return "UERadioCapabilityIDMappingRequestIEs"
	case "UERadioCapabilityIDMappingResponse":
		return "UERadioCapabilityIDMappingResponseIEs"
	case "UERadioCapabilityIDMappingResponseIEs":
		return "UERadioCapabilityIDMappingResponseIEs"
	case "X2APMessageTransfer":
		return "X2APMessageTransfer-IEs"
	case "X2APMessageTransfer-IEs":
		return "X2APMessageTransfer-IEs"
	case "X2Release":
		return "X2Release-IEs"
	case "X2Release-IEs":
		return "X2Release-IEs"
	case "X2RemovalFailure":
		return "X2RemovalFailure-IEs"
	case "X2RemovalFailure-IEs":
		return "X2RemovalFailure-IEs"
	case "X2RemovalRequest":
		return "X2RemovalRequest-IEs"
	case "X2RemovalRequest-IEs":
		return "X2RemovalRequest-IEs"
	case "X2RemovalResponse":
		return "X2RemovalResponse-IEs"
	case "X2RemovalResponse-IEs":
		return "X2RemovalResponse-IEs"
	case "X2SetupFailure":
		return "X2SetupFailure-IEs"
	case "X2SetupFailure-IEs":
		return "X2SetupFailure-IEs"
	case "X2SetupRequest":
		return "X2SetupRequest-IEs"
	case "X2SetupRequest-IEs":
		return "X2SetupRequest-IEs"
	case "X2SetupResponse":
		return "X2SetupResponse-IEs"
	case "X2SetupResponse-IEs":
		return "X2SetupResponse-IEs"
	default:
		return context
	}
}

func protocolExtensionObjectSet(context string) string {
	switch context {
	case "CHOinformation-REQ-ExtIEs":
		return "CHOinformation-REQ-ExtIEs"
	case "CHOinformationREQExtIEs":
		return "CHOinformation-REQ-ExtIEs"
	case "CellInformation-Item-ExtIEs":
		return "CellInformation-Item-ExtIEs"
	case "CellInformationItemExtIEs":
		return "CellInformation-Item-ExtIEs"
	case "CellMeasurementResult-Item-ExtIEs":
		return "CellMeasurementResult-Item-ExtIEs"
	case "CellMeasurementResultItemExtIEs":
		return "CellMeasurementResult-Item-ExtIEs"
	case "E-RAB-Level-QoS-Parameters-ExtIEs":
		return "E-RAB-Level-QoS-Parameters-ExtIEs"
	case "E-RABs-Admitted-Item-ExtIEs":
		return "E-RABs-Admitted-Item-ExtIEs"
	case "E-RABs-Admitted-ToBeAdded-Item-SCG-BearerExtIEs":
		return "E-RABs-Admitted-ToBeAdded-Item-SCG-BearerExtIEs"
	case "E-RABs-Admitted-ToBeAdded-Item-Split-BearerExtIEs":
		return "E-RABs-Admitted-ToBeAdded-Item-Split-BearerExtIEs"
	case "E-RABs-Admitted-ToBeAdded-ModAckItem-SCG-BearerExtIEs":
		return "E-RABs-Admitted-ToBeAdded-ModAckItem-SCG-BearerExtIEs"
	case "E-RABs-Admitted-ToBeAdded-ModAckItem-Split-BearerExtIEs":
		return "E-RABs-Admitted-ToBeAdded-ModAckItem-Split-BearerExtIEs"
	case "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item-SgNBPDCPnotpresentExtIEs":
		return "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item-SgNBPDCPnotpresentExtIEs"
	case "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item-SgNBPDCPpresentExtIEs":
		return "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item-SgNBPDCPpresentExtIEs"
	case "E-RABs-Admitted-ToBeAdded-SgNBModAck-Item-SgNBPDCPnotpresentExtIEs":
		return "E-RABs-Admitted-ToBeAdded-SgNBModAck-Item-SgNBPDCPnotpresentExtIEs"
	case "E-RABs-Admitted-ToBeAdded-SgNBModAck-Item-SgNBPDCPpresentExtIEs":
		return "E-RABs-Admitted-ToBeAdded-SgNBModAck-Item-SgNBPDCPpresentExtIEs"
	case "E-RABs-Admitted-ToBeModified-SgNBModAck-Item-SgNBPDCPnotpresentExtIEs":
		return "E-RABs-Admitted-ToBeModified-SgNBModAck-Item-SgNBPDCPnotpresentExtIEs"
	case "E-RABs-Admitted-ToBeModified-SgNBModAck-Item-SgNBPDCPpresentExtIEs":
		return "E-RABs-Admitted-ToBeModified-SgNBModAck-Item-SgNBPDCPpresentExtIEs"
	case "E-RABs-AdmittedToBeModified-SgNBModConf-Item-SgNBPDCPnotpresentExtIEs":
		return "E-RABs-AdmittedToBeModified-SgNBModConf-Item-SgNBPDCPnotpresentExtIEs"
	case "E-RABs-SubjectToStatusTransfer-ItemExtIEs":
		return "E-RABs-SubjectToStatusTransfer-ItemExtIEs"
	case "E-RABs-ToBeAdded-Item-SCG-BearerExtIEs":
		return "E-RABs-ToBeAdded-Item-SCG-BearerExtIEs"
	case "E-RABs-ToBeAdded-Item-Split-BearerExtIEs":
		return "E-RABs-ToBeAdded-Item-Split-BearerExtIEs"
	case "E-RABs-ToBeAdded-ModReqItem-SCG-BearerExtIEs":
		return "E-RABs-ToBeAdded-ModReqItem-SCG-BearerExtIEs"
	case "E-RABs-ToBeAdded-ModReqItem-Split-BearerExtIEs":
		return "E-RABs-ToBeAdded-ModReqItem-Split-BearerExtIEs"
	case "E-RABs-ToBeAdded-SgNBAddReq-Item-SgNBPDCPnotpresentExtIEs":
		return "E-RABs-ToBeAdded-SgNBAddReq-Item-SgNBPDCPnotpresentExtIEs"
	case "E-RABs-ToBeAdded-SgNBAddReq-Item-SgNBPDCPpresentExtIEs":
		return "E-RABs-ToBeAdded-SgNBAddReq-Item-SgNBPDCPpresentExtIEs"
	case "E-RABs-ToBeAdded-SgNBModReq-Item-SgNBPDCPnotpresentExtIEs":
		return "E-RABs-ToBeAdded-SgNBModReq-Item-SgNBPDCPnotpresentExtIEs"
	case "E-RABs-ToBeAdded-SgNBModReq-Item-SgNBPDCPpresentExtIEs":
		return "E-RABs-ToBeAdded-SgNBModReq-Item-SgNBPDCPpresentExtIEs"
	case "E-RABs-ToBeModified-SgNBModReq-Item-SgNBPDCPnotpresentExtIEs":
		return "E-RABs-ToBeModified-SgNBModReq-Item-SgNBPDCPnotpresentExtIEs"
	case "E-RABs-ToBeModified-SgNBModReq-Item-SgNBPDCPpresentExtIEs":
		return "E-RABs-ToBeModified-SgNBModReq-Item-SgNBPDCPpresentExtIEs"
	case "E-RABs-ToBeModified-SgNBModReqd-Item-SgNBPDCPnotpresentExtIEs":
		return "E-RABs-ToBeModified-SgNBModReqd-Item-SgNBPDCPnotpresentExtIEs"
	case "E-RABs-ToBeModified-SgNBModReqd-Item-SgNBPDCPpresentExtIEs":
		return "E-RABs-ToBeModified-SgNBModReqd-Item-SgNBPDCPpresentExtIEs"
	case "E-RABs-ToBeReleased-SgNBChaConf-Item-SgNBPDCPpresentExtIEs":
		return "E-RABs-ToBeReleased-SgNBChaConf-Item-SgNBPDCPpresentExtIEs"
	case "E-RABs-ToBeReleased-SgNBModReqd-ItemExtIEs":
		return "E-RABs-ToBeReleased-SgNBModReqd-ItemExtIEs"
	case "E-RABs-ToBeSetup-ItemExtIEs":
		return "E-RABs-ToBeSetup-ItemExtIEs"
	case "E-RABs-ToBeSetupRetrieve-ItemExtIEs":
		return "E-RABs-ToBeSetupRetrieve-ItemExtIEs"
	case "ERABLevelQoSParametersExtIEs":
		return "E-RAB-Level-QoS-Parameters-ExtIEs"
	case "ERABsAdmittedItemExtIEs":
		return "E-RABs-Admitted-Item-ExtIEs"
	case "ERABsAdmittedToBeAddedItemSCGBearerExtIEs":
		return "E-RABs-Admitted-ToBeAdded-Item-SCG-BearerExtIEs"
	case "ERABsAdmittedToBeAddedItemSplitBearerExtIEs":
		return "E-RABs-Admitted-ToBeAdded-Item-Split-BearerExtIEs"
	case "ERABsAdmittedToBeAddedModAckItemSCGBearerExtIEs":
		return "E-RABs-Admitted-ToBeAdded-ModAckItem-SCG-BearerExtIEs"
	case "ERABsAdmittedToBeAddedModAckItemSplitBearerExtIEs":
		return "E-RABs-Admitted-ToBeAdded-ModAckItem-Split-BearerExtIEs"
	case "ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPnotpresentExtIEs":
		return "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item-SgNBPDCPnotpresentExtIEs"
	case "ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPpresentExtIEs":
		return "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item-SgNBPDCPpresentExtIEs"
	case "ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPnotpresentExtIEs":
		return "E-RABs-Admitted-ToBeAdded-SgNBModAck-Item-SgNBPDCPnotpresentExtIEs"
	case "ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPpresentExtIEs":
		return "E-RABs-Admitted-ToBeAdded-SgNBModAck-Item-SgNBPDCPpresentExtIEs"
	case "ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPnotpresentExtIEs":
		return "E-RABs-Admitted-ToBeModified-SgNBModAck-Item-SgNBPDCPnotpresentExtIEs"
	case "ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPpresentExtIEs":
		return "E-RABs-Admitted-ToBeModified-SgNBModAck-Item-SgNBPDCPpresentExtIEs"
	case "ERABsAdmittedToBeModifiedSgNBModConfItemSgNBPDCPnotpresentExtIEs":
		return "E-RABs-AdmittedToBeModified-SgNBModConf-Item-SgNBPDCPnotpresentExtIEs"
	case "ERABsSubjectToStatusTransferItemExtIEs":
		return "E-RABs-SubjectToStatusTransfer-ItemExtIEs"
	case "ERABsToBeAddedItemSCGBearerExtIEs":
		return "E-RABs-ToBeAdded-Item-SCG-BearerExtIEs"
	case "ERABsToBeAddedItemSplitBearerExtIEs":
		return "E-RABs-ToBeAdded-Item-Split-BearerExtIEs"
	case "ERABsToBeAddedModReqItemSCGBearerExtIEs":
		return "E-RABs-ToBeAdded-ModReqItem-SCG-BearerExtIEs"
	case "ERABsToBeAddedModReqItemSplitBearerExtIEs":
		return "E-RABs-ToBeAdded-ModReqItem-Split-BearerExtIEs"
	case "ERABsToBeAddedSgNBAddReqItemSgNBPDCPnotpresentExtIEs":
		return "E-RABs-ToBeAdded-SgNBAddReq-Item-SgNBPDCPnotpresentExtIEs"
	case "ERABsToBeAddedSgNBAddReqItemSgNBPDCPpresentExtIEs":
		return "E-RABs-ToBeAdded-SgNBAddReq-Item-SgNBPDCPpresentExtIEs"
	case "ERABsToBeAddedSgNBModReqItemSgNBPDCPnotpresentExtIEs":
		return "E-RABs-ToBeAdded-SgNBModReq-Item-SgNBPDCPnotpresentExtIEs"
	case "ERABsToBeAddedSgNBModReqItemSgNBPDCPpresentExtIEs":
		return "E-RABs-ToBeAdded-SgNBModReq-Item-SgNBPDCPpresentExtIEs"
	case "ERABsToBeModifiedSgNBModReqItemSgNBPDCPnotpresentExtIEs":
		return "E-RABs-ToBeModified-SgNBModReq-Item-SgNBPDCPnotpresentExtIEs"
	case "ERABsToBeModifiedSgNBModReqItemSgNBPDCPpresentExtIEs":
		return "E-RABs-ToBeModified-SgNBModReq-Item-SgNBPDCPpresentExtIEs"
	case "ERABsToBeModifiedSgNBModReqdItemSgNBPDCPnotpresentExtIEs":
		return "E-RABs-ToBeModified-SgNBModReqd-Item-SgNBPDCPnotpresentExtIEs"
	case "ERABsToBeModifiedSgNBModReqdItemSgNBPDCPpresentExtIEs":
		return "E-RABs-ToBeModified-SgNBModReqd-Item-SgNBPDCPpresentExtIEs"
	case "ERABsToBeReleasedSgNBChaConfItemSgNBPDCPpresentExtIEs":
		return "E-RABs-ToBeReleased-SgNBChaConf-Item-SgNBPDCPpresentExtIEs"
	case "ERABsToBeReleasedSgNBModReqdItemExtIEs":
		return "E-RABs-ToBeReleased-SgNBModReqd-ItemExtIEs"
	case "ERABsToBeSetupItemExtIEs":
		return "E-RABs-ToBeSetup-ItemExtIEs"
	case "ERABsToBeSetupRetrieveItemExtIEs":
		return "E-RABs-ToBeSetupRetrieve-ItemExtIEs"
	case "En-gNBServedCells-ExtIEs":
		return "En-gNBServedCells-ExtIEs"
	case "EnGNBServedCellsExtIEs":
		return "En-gNBServedCells-ExtIEs"
	case "FDD-Info-ExtIEs":
		return "FDD-Info-ExtIEs"
	case "FDD-InfoNeighbourServedNRCell-Information-ExtIEs":
		return "FDD-InfoNeighbourServedNRCell-Information-ExtIEs"
	case "FDD-InfoServedNRCell-Information-ExtIEs":
		return "FDD-InfoServedNRCell-Information-ExtIEs"
	case "FDDInfoExtIEs":
		return "FDD-Info-ExtIEs"
	case "FDDInfoNeighbourServedNRCellInformationExtIEs":
		return "FDD-InfoNeighbourServedNRCell-Information-ExtIEs"
	case "FDDInfoServedNRCellInformationExtIEs":
		return "FDD-InfoServedNRCell-Information-ExtIEs"
	case "GBR-QosInformation-ExtIEs":
		return "GBR-QosInformation-ExtIEs"
	case "GBRQosInformationExtIEs":
		return "GBR-QosInformation-ExtIEs"
	case "GTPtunnelEndpoint-ExtIEs":
		return "GTPtunnelEndpoint-ExtIEs"
	case "GTPtunnelEndpointExtIEs":
		return "GTPtunnelEndpoint-ExtIEs"
	case "HandoverRestrictionList-ExtIEs":
		return "HandoverRestrictionList-ExtIEs"
	case "HandoverRestrictionListExtIEs":
		return "HandoverRestrictionList-ExtIEs"
	case "LastVisitedEUTRANCellInformation-ExtIEs":
		return "LastVisitedEUTRANCellInformation-ExtIEs"
	case "LastVisitedEUTRANCellInformationExtIEs":
		return "LastVisitedEUTRANCellInformation-ExtIEs"
	case "LocationReportingInformation-ExtIEs":
		return "LocationReportingInformation-ExtIEs"
	case "LocationReportingInformationExtIEs":
		return "LocationReportingInformation-ExtIEs"
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
	case "MeNBResourceCoordinationInformationExtIEs":
		return "MeNBResourceCoordinationInformationExtIEs"
	case "NRFreqInfo-ExtIEs":
		return "NRFreqInfo-ExtIEs"
	case "NRFreqInfoExtIEs":
		return "NRFreqInfo-ExtIEs"
	case "NRNeighbour-Information-ExtIEs":
		return "NRNeighbour-Information-ExtIEs"
	case "NRNeighbourInformationExtIEs":
		return "NRNeighbour-Information-ExtIEs"
	case "NRRAReportList-Item-ExtIEs":
		return "NRRAReportList-Item-ExtIEs"
	case "NRRAReportListItemExtIEs":
		return "NRRAReportList-Item-ExtIEs"
	case "NRRadioResourceStatus-ExtIEs":
		return "NRRadioResourceStatus-ExtIEs"
	case "NRRadioResourceStatusExtIEs":
		return "NRRadioResourceStatus-ExtIEs"
	case "Neighbour-Information-ExtIEs":
		return "Neighbour-Information-ExtIEs"
	case "NeighbourInformationExtIEs":
		return "Neighbour-Information-ExtIEs"
	case "ProSeAuthorized-ExtIEs":
		return "ProSeAuthorized-ExtIEs"
	case "ProSeAuthorizedExtIEs":
		return "ProSeAuthorized-ExtIEs"
	case "RSRPMRList-ExtIEs":
		return "RSRPMRList-ExtIEs"
	case "RSRPMRListExtIEs":
		return "RSRPMRList-ExtIEs"
	case "RadioResourceStatus-ExtIEs":
		return "RadioResourceStatus-ExtIEs"
	case "RadioResourceStatusExtIEs":
		return "RadioResourceStatus-ExtIEs"
	case "RelativeNarrowbandTxPower-ExtIEs":
		return "RelativeNarrowbandTxPower-ExtIEs"
	case "RelativeNarrowbandTxPowerExtIEs":
		return "RelativeNarrowbandTxPower-ExtIEs"
	case "SULInformation-ExtIEs":
		return "SULInformation-ExtIEs"
	case "SULInformationExtIEs":
		return "SULInformation-ExtIEs"
	case "ServedCell-ExtIEs":
		return "ServedCell-ExtIEs"
	case "ServedCell-Information-ExtIEs":
		return "ServedCell-Information-ExtIEs"
	case "ServedCellExtIEs":
		return "ServedCell-ExtIEs"
	case "ServedCellInformationExtIEs":
		return "ServedCell-Information-ExtIEs"
	case "ServedCellsToModify-Item-ExtIEs":
		return "ServedCellsToModify-Item-ExtIEs"
	case "ServedCellsToModifyItemExtIEs":
		return "ServedCellsToModify-Item-ExtIEs"
	case "ServedNRCell-Information-ExtIEs":
		return "ServedNRCell-Information-ExtIEs"
	case "ServedNRCellInformationExtIEs":
		return "ServedNRCell-Information-ExtIEs"
	case "SgNBResourceCoordinationInformationExtIEs":
		return "SgNBResourceCoordinationInformationExtIEs"
	case "TDD-Info-ExtIEs":
		return "TDD-Info-ExtIEs"
	case "TDD-InfoNeighbourServedNRCell-Information-ExtIEs":
		return "TDD-InfoNeighbourServedNRCell-Information-ExtIEs"
	case "TDD-InfoServedNRCell-Information-ExtIEs":
		return "TDD-InfoServedNRCell-Information-ExtIEs"
	case "TDDInfoExtIEs":
		return "TDD-Info-ExtIEs"
	case "TDDInfoNeighbourServedNRCellInformationExtIEs":
		return "TDD-InfoNeighbourServedNRCell-Information-ExtIEs"
	case "TDDInfoServedNRCellInformationExtIEs":
		return "TDD-InfoServedNRCell-Information-ExtIEs"
	case "TraceActivation-ExtIEs":
		return "TraceActivation-ExtIEs"
	case "TraceActivationExtIEs":
		return "TraceActivation-ExtIEs"
	case "UE-ContextInformation-ExtIEs":
		return "UE-ContextInformation-ExtIEs"
	case "UE-ContextInformationRetrieve-ExtIEs":
		return "UE-ContextInformationRetrieve-ExtIEs"
	case "UE-ContextInformationSgNBModReqExtIEs":
		return "UE-ContextInformationSgNBModReqExtIEs"
	case "UEAggregate-MaximumBitrate-ExtIEs":
		return "UEAggregate-MaximumBitrate-ExtIEs"
	case "UEAggregateMaximumBitrateExtIEs":
		return "UEAggregate-MaximumBitrate-ExtIEs"
	case "UEAppLayerMeasConfig-ExtIEs":
		return "UEAppLayerMeasConfig-ExtIEs"
	case "UEAppLayerMeasConfigExtIEs":
		return "UEAppLayerMeasConfig-ExtIEs"
	case "UEContextInformationExtIEs":
		return "UE-ContextInformation-ExtIEs"
	case "UEContextInformationRetrieveExtIEs":
		return "UE-ContextInformationRetrieve-ExtIEs"
	case "UEContextInformationSgNBModReqExtIEs":
		return "UE-ContextInformationSgNBModReqExtIEs"
	default:
		return context
	}
}

func protocolIEValueTypeHint(objectSet string, id int64) protocolOpenTypeHint {
	switch objectSet {
	case "DataForwardingAddressIndication-IEs":
		switch id {
		case 307:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-DataForwardingAddress-ItemIEs", typeName: "ERABsDataForwardingAddressList"}
		}
	case "ENDCResourceStatusRequest-IEs":
		switch id {
		case 391:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "CellToReport-NR-ENDC-ItemIEs", typeName: "CellToReportNRENDCList"}
		case 403:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "CellToReport-E-UTRA-ENDC-Item-IEs", typeName: "CellToReportEUTRAENDCList"}
		}
	case "ENDCResourceStatusUpdate-IEs":
		switch id {
		case 393:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "CellMeasurementResult-NR-ENDC-ItemIEs", typeName: "CellMeasurementResultNRENDCList"}
		case 401:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "CellMeasurementResult-E-UTRA-ENDC-ItemIEs", typeName: "CellMeasurementResultEUTRAENDCList"}
		}
	case "HandoverRequestAcknowledge-IEs":
		switch id {
		case 1:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-Admitted-ItemIEs", typeName: "ERABsAdmittedList"}
		case 3:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RAB-ItemIEs", typeName: "ERABList"}
		case 339:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RAB-ItemIEs", typeName: "ERABList"}
		}
	case "LoadInformation-IEs":
		switch id {
		case 6:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "CellInformation-ItemIEs", typeName: "CellInformationList"}
		}
	case "ResourceStatusFailure-IEs":
		switch id {
		case 68:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "CompleteFailureCauseInformation-ItemIEs", typeName: "CompleteFailureCauseInformationList"}
		}
	case "ResourceStatusRequest-IEs":
		switch id {
		case 29:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "CellToReport-ItemIEs", typeName: "CellToReportList"}
		}
	case "ResourceStatusResponse-IEs":
		switch id {
		case 65:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "MeasurementInitiationResult-ItemIEs", typeName: "MeasurementInitiationResultList"}
		}
	case "ResourceStatusUpdate-IEs":
		switch id {
		case 32:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "CellMeasurementResult-ItemIEs", typeName: "CellMeasurementResultList"}
		}
	case "SNStatusTransfer-IEs":
		switch id {
		case 18:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-SubjectToStatusTransfer-ItemIEs", typeName: "ERABsSubjectToStatusTransferList"}
		}
	case "SeNBAdditionRequest-IEs":
		switch id {
		case 117:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-ToBeAdded-ItemIEs", typeName: "ERABsToBeAddedList"}
		}
	case "SeNBAdditionRequestAcknowledge-IEs":
		switch id {
		case 3:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RAB-ItemIEs", typeName: "ERABList"}
		case 120:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-Admitted-ToBeAdded-ItemIEs", typeName: "ERABsAdmittedToBeAddedList"}
		}
	case "SeNBCounterCheckRequest-IEs":
		switch id {
		case 141:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-SubjectToCounterCheckItemIEs", typeName: "ERABsSubjectToCounterCheckList"}
		}
	case "SeNBModificationRequestAcknowledge-IEs":
		switch id {
		case 3:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RAB-ItemIEs", typeName: "ERABList"}
		case 128:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-Admitted-ToBeAdded-ModAckItemIEs", typeName: "ERABsAdmittedToBeAddedModAckList"}
		case 129:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-Admitted-ToBeModified-ModAckItemIEs", typeName: "ERABsAdmittedToBeModifiedModAckList"}
		case 130:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-Admitted-ToBeReleased-ModAckItemIEs", typeName: "ERABsAdmittedToBeReleasedModAckList"}
		}
	case "SeNBModificationRequired-IEs":
		switch id {
		case 134:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-ToBeReleased-ModReqdItemIEs", typeName: "ERABsToBeReleasedModReqd"}
		}
	case "SeNBReleaseConfirm-IEs":
		switch id {
		case 139:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-ToBeReleased-RelConfItemIEs", typeName: "ERABsToBeReleasedListRelConf"}
		}
	case "SeNBReleaseRequest-IEs":
		switch id {
		case 137:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-ToBeReleased-RelReqItemIEs", typeName: "ERABsToBeReleasedListRelReq"}
		}
	case "SecondaryRATDataUsageReport-IEs":
		switch id {
		case 265:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "SecondaryRATUsageReport-ItemIEs", typeName: "SecondaryRATUsageReportList"}
		}
	case "SgNBAdditionRequest-IEs":
		switch id {
		case 205:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-ToBeAdded-SgNBAddReq-ItemIEs", typeName: "ERABsToBeAddedSgNBAddReqList"}
		}
	case "SgNBAdditionRequestAcknowledge-IEs":
		switch id {
		case 3:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RAB-ItemIEs", typeName: "ERABList"}
		case 210:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-ItemIEs", typeName: "ERABsAdmittedToBeAddedSgNBAddReqAckList"}
		}
	case "SgNBChangeConfirm-IEs":
		switch id {
		case 229:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-ToBeReleased-SgNBChaConf-ItemIEs", typeName: "ERABsToBeReleasedSgNBChaConfList"}
		}
	case "SgNBCounterCheckRequest-IEs":
		switch id {
		case 235:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-SubjectToSgNBCounterCheck-ItemIEs", typeName: "ERABsSubjectToSgNBCounterCheckList"}
		}
	case "SgNBModificationConfirm-IEs":
		switch id {
		case 294:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-AdmittedToBeModified-SgNBModConf-ItemIEs", typeName: "ERABsAdmittedToBeModifiedSgNBModConfList"}
		}
	case "SgNBModificationRequestAcknowledge-IEs":
		switch id {
		case 3:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RAB-ItemIEs", typeName: "ERABList"}
		case 219:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-Admitted-ToBeAdded-SgNBModAck-ItemIEs", typeName: "ERABsAdmittedToBeAddedSgNBModAckList"}
		case 220:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-Admitted-ToBeModified-SgNBModAck-ItemIEs", typeName: "ERABsAdmittedToBeModifiedSgNBModAckList"}
		case 221:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-Admitted-ToBeReleased-SgNBModAck-ItemIEs", typeName: "ERABsAdmittedToBeReleasedSgNBModAckList"}
		}
	case "SgNBModificationRequired-IEs":
		switch id {
		case 225:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-ToBeReleased-SgNBModReqd-ItemIEs", typeName: "ERABsToBeReleasedSgNBModReqdList"}
		case 226:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-ToBeModified-SgNBModReqd-ItemIEs", typeName: "ERABsToBeModifiedSgNBModReqdList"}
		}
	case "SgNBReleaseConfirm-IEs":
		switch id {
		case 233:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-ToBeReleased-SgNBRelConf-ItemIEs", typeName: "ERABsToBeReleasedSgNBRelConfList"}
		}
	case "SgNBReleaseRequest-IEs":
		switch id {
		case 231:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-ToBeReleased-SgNBRelReq-ItemIEs", typeName: "ERABsToBeReleasedSgNBRelReqList"}
		case 339:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RAB-ItemIEs", typeName: "ERABList"}
		}
	case "SgNBReleaseRequestAcknowledge-IEs":
		switch id {
		case 318:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-Admitted-ToBeReleased-SgNBRelReqAck-ItemIEs", typeName: "ERABsAdmittedToBeReleasedSgNBRelReqAckList"}
		}
	case "SgNBReleaseRequired-IEs":
		switch id {
		case 320:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "E-RABs-ToBeReleased-SgNBRelReqd-ItemIEs", typeName: "ERABsToBeReleasedSgNBRelReqdList"}
		}
	}
	return protocolOpenTypeHint{}
}

func protocolExtensionValueTypeHint(objectSet string, id int64) protocolOpenTypeHint {
	switch objectSet {
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
