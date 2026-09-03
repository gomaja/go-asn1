// Code generated from ASN.1. DO NOT EDIT.

package x2ap

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
	case "E-RAB-ItemIEs":
		switch ieId {
		case 2: // id-E-RAB-Item -> ERABItem
			var v ERABItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABUsageReport-ItemIEs":
		switch ieId {
		case 263: // id-E-RABUsageReport-Item -> ERABUsageReportItem
			var v ERABUsageReportItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABUsageReportItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SecondaryRATUsageReport-ItemIEs":
		switch ieId {
		case 266: // id-SecondaryRATUsageReport-Item -> SecondaryRATUsageReportItem
			var v SecondaryRATUsageReportItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SecondaryRATUsageReportItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverRequest-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
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
		case 15: // id-UE-HistoryInformation -> UEHistoryInformation (SEQUENCE_OF)
			v, err := UnmarshalAPERUEHistoryInformationFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEHistoryInformation (%d): %w", ieId, err)
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
		case 98: // id-Masked-IMEISV -> MaskedIMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MaskedIMEISV (%d): %w", ieId, err)
			}
			result := MaskedIMEISV{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 105: // id-UE-HistoryInformationFromTheUE -> UEHistoryInformationFromTheUE (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEHistoryInformationFromTheUE (%d): %w", ieId, err)
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
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
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
		case 309: // id-Subscription-Based-UE-DifferentiationInfo -> SubscriptionBasedUEDifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SubscriptionBasedUEDifferentiationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 361: // id-CHOinformation-REQ -> CHOinformationREQ
			var v CHOinformationREQ
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CHOinformationREQ (%d): %w", ieId, err)
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
	case "E-RABs-ToBeSetup-ItemIEs":
		switch ieId {
		case 4: // id-E-RABs-ToBeSetup-Item -> ERABsToBeSetupItem
			var v ERABsToBeSetupItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeSetupItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverRequestAcknowledge-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 1: // id-E-RABs-Admitted-List -> ERABsAdmittedList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedList (%d): %w", ieId, err)
			}
			return &v, nil
		case 3: // id-E-RABs-NotAdmitted-List -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 12: // id-TargeteNBtoSource-eNBTransparentContainer -> TargeteNBtoSourceENBTransparentContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TargeteNBtoSourceENBTransparentContainer (%d): %w", ieId, err)
			}
			result := TargeteNBtoSourceENBTransparentContainer(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 154: // id-UE-ContextKeptIndicator -> UEContextKeptIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEContextKeptIndicator (%d): %w", ieId, err)
			}
			result := UEContextKeptIndicator(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 183: // id-WT-UE-ContextKeptIndicator -> UEContextKeptIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEContextKeptIndicator (%d): %w", ieId, err)
			}
			result := UEContextKeptIndicator(v)
			return &result, nil
		case 339: // id-ERABs-transferred-to-MeNB -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
			}
			return &v, nil
		case 362: // id-CHOinformation-ACK -> CHOinformationACK
			var v CHOinformationACK
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CHOinformationACK (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-Admitted-ItemIEs":
		switch ieId {
		case 0: // id-E-RABs-Admitted-Item -> ERABsAdmittedItem
			var v ERABsAdmittedItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverPreparationFailure-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
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
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 364: // id-RequestedTargetCellID -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverReport-IEs":
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
		case 60: // id-UE-RLF-Report-Container -> UERLFReportContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERLFReportContainer (%d): %w", ieId, err)
			}
			result := UERLFReportContainer(v)
			return &result, nil
		case 107: // id-UE-RLF-Report-Container-for-extended-bands -> UERLFReportContainerForExtendedBands (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERLFReportContainerForExtendedBands (%d): %w", ieId, err)
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
	case "EarlyStatusTransfer-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 367: // id-ProcedureStage -> ProcedureStageChoice
			var v ProcedureStageChoice
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ProcedureStageChoice (%d): %w", ieId, err)
			}
			return &v, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		}
	case "SNStatusTransfer-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 18: // id-E-RABs-SubjectToStatusTransfer-List -> ERABsSubjectToStatusTransferList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsSubjectToStatusTransferList (%d): %w", ieId, err)
			}
			return &v, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		}
	case "E-RABs-SubjectToStatusTransfer-ItemIEs":
		switch ieId {
		case 19: // id-E-RABs-SubjectToStatusTransfer-Item -> ERABsSubjectToStatusTransferItem
			var v ERABsSubjectToStatusTransferItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsSubjectToStatusTransferItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UEContextRelease-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 164: // id-SIPTO-BearerDeactivationIndication -> SIPTOBearerDeactivationIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SIPTOBearerDeactivationIndication (%d): %w", ieId, err)
			}
			result := SIPTOBearerDeactivationIndication(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		}
	case "HandoverCancel-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 365: // id-CandidateCellsToBeCancelledList -> CandidateCellsToBeCancelledList (SEQUENCE_OF)
			v, err := UnmarshalAPERCandidateCellsToBeCancelledListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CandidateCellsToBeCancelledList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "HandoverSuccess-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 11: // id-TargetCell-ID -> ECGI
			var v ECGI
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ECGI (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ConditionalHandoverCancel-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 365: // id-CandidateCellsToBeCancelledList -> CandidateCellsToBeCancelledList (SEQUENCE_OF)
			v, err := UnmarshalAPERCandidateCellsToBeCancelledListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CandidateCellsToBeCancelledList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ErrorIndication-IEs":
		switch ieId {
		case 10: // id-Old-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 9: // id-New-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
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
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 264: // id-Old-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ResetRequest-IEs":
		switch ieId {
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ResetResponse-IEs":
		switch ieId {
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "X2SetupRequest-IEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENBID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENBID (%d): %w", ieId, err)
			}
			return &v, nil
		case 20: // id-ServedCells -> ServedCells (SEQUENCE_OF)
			v, err := UnmarshalAPERServedCellsFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedCells (%d): %w", ieId, err)
			}
			return &v, nil
		case 24: // id-GUGroupIDList -> GUGroupIDList (SEQUENCE_OF)
			v, err := UnmarshalAPERGUGroupIDListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GUGroupIDList (%d): %w", ieId, err)
			}
			return &v, nil
		case 159: // id-LHN-ID -> LHNID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 32, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LHNID (%d): %w", ieId, err)
			}
			result := LHNID(v)
			return &result, nil
		}
	case "X2SetupResponse-IEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENBID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENBID (%d): %w", ieId, err)
			}
			return &v, nil
		case 20: // id-ServedCells -> ServedCells (SEQUENCE_OF)
			v, err := UnmarshalAPERServedCellsFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedCells (%d): %w", ieId, err)
			}
			return &v, nil
		case 24: // id-GUGroupIDList -> GUGroupIDList (SEQUENCE_OF)
			v, err := UnmarshalAPERGUGroupIDListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GUGroupIDList (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 159: // id-LHN-ID -> LHNID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 32, 256, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE LHNID (%d): %w", ieId, err)
			}
			result := LHNID(v)
			return &result, nil
		}
	case "X2SetupFailure-IEs":
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
	case "LoadInformation-IEs":
		switch ieId {
		case 6: // id-CellInformation -> CellInformationList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellInformationList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CellInformation-ItemIEs":
		switch ieId {
		case 7: // id-CellInformation-Item -> CellInformationItem
			var v CellInformationItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellInformationItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENBConfigurationUpdate-IEs":
		switch ieId {
		case 25: // id-ServedCellsToAdd -> ServedCells (SEQUENCE_OF)
			v, err := UnmarshalAPERServedCellsFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedCells (%d): %w", ieId, err)
			}
			return &v, nil
		case 26: // id-ServedCellsToModify -> ServedCellsToModify (SEQUENCE_OF)
			v, err := UnmarshalAPERServedCellsToModifyFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedCellsToModify (%d): %w", ieId, err)
			}
			return &v, nil
		case 27: // id-ServedCellsToDelete -> OldECGIs (SEQUENCE_OF)
			v, err := UnmarshalAPEROldECGIsFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE OldECGIs (%d): %w", ieId, err)
			}
			return &v, nil
		case 34: // id-GUGroupIDToAddList -> GUGroupIDList (SEQUENCE_OF)
			v, err := UnmarshalAPERGUGroupIDListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GUGroupIDList (%d): %w", ieId, err)
			}
			return &v, nil
		case 35: // id-GUGroupIDToDeleteList -> GUGroupIDList (SEQUENCE_OF)
			v, err := UnmarshalAPERGUGroupIDListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GUGroupIDList (%d): %w", ieId, err)
			}
			return &v, nil
		case 143: // id-CoverageModificationList -> CoverageModificationList (SEQUENCE_OF)
			v, err := UnmarshalAPERCoverageModificationListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CoverageModificationList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENBConfigurationUpdateAcknowledge-IEs":
		switch ieId {
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENBConfigurationUpdateFailure-IEs":
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
	case "ResourceStatusRequest-IEs":
		switch ieId {
		case 39: // id-ENB1-Measurement-ID -> MeasurementID (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		case 40: // id-ENB2-Measurement-ID -> MeasurementID (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		case 28: // id-Registration-Request -> RegistrationRequest (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RegistrationRequest (%d): %w", ieId, err)
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
	case "CellToReport-ItemIEs":
		switch ieId {
		case 31: // id-CellToReport-Item -> CellToReportItem
			var v CellToReportItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellToReportItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ResourceStatusResponse-IEs":
		switch ieId {
		case 39: // id-ENB1-Measurement-ID -> MeasurementID (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		case 40: // id-ENB2-Measurement-ID -> MeasurementID (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
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
	case "MeasurementInitiationResult-ItemIEs":
		switch ieId {
		case 66: // id-MeasurementInitiationResult-Item -> MeasurementInitiationResultItem
			var v MeasurementInitiationResultItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementInitiationResultItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MeasurementFailureCause-ItemIEs":
		switch ieId {
		case 67: // id-MeasurementFailureCause-Item -> MeasurementFailureCauseItem
			var v MeasurementFailureCauseItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementFailureCauseItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ResourceStatusFailure-IEs":
		switch ieId {
		case 39: // id-ENB1-Measurement-ID -> MeasurementID (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		case 40: // id-ENB2-Measurement-ID -> MeasurementID (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
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
	case "CompleteFailureCauseInformation-ItemIEs":
		switch ieId {
		case 69: // id-CompleteFailureCauseInformation-Item -> CompleteFailureCauseInformationItem
			var v CompleteFailureCauseInformationItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CompleteFailureCauseInformationItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ResourceStatusUpdate-IEs":
		switch ieId {
		case 39: // id-ENB1-Measurement-ID -> MeasurementID (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		case 40: // id-ENB2-Measurement-ID -> MeasurementID (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		case 32: // id-CellMeasurementResult -> CellMeasurementResultList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellMeasurementResultList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CellMeasurementResult-ItemIEs":
		switch ieId {
		case 33: // id-CellMeasurementResult-Item -> CellMeasurementResultItem
			var v CellMeasurementResultItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellMeasurementResultItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MobilityChangeRequest-IEs":
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
	case "MobilityChangeAcknowledge-IEs":
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
	case "MobilityChangeFailure-IEs":
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
	case "RLFIndication-IEs":
		switch ieId {
		case 48: // id-FailureCellPCI -> PCI (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("503"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PCI (%d): %w", ieId, err)
			}
			return v, nil
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
		case 51: // id-ShortMAC-I -> ShortMACI (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ShortMACI (%d): %w", ieId, err)
			}
			result := ShortMACI{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 60: // id-UE-RLF-Report-Container -> UERLFReportContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERLFReportContainer (%d): %w", ieId, err)
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
		case 107: // id-UE-RLF-Report-Container-for-extended-bands -> UERLFReportContainerForExtendedBands (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERLFReportContainerForExtendedBands (%d): %w", ieId, err)
			}
			result := UERLFReportContainerForExtendedBands(v)
			return &result, nil
		case 374: // id-NBIoT-RLF-Report-Container -> NBIoTRLFReportContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NBIoTRLFReportContainer (%d): %w", ieId, err)
			}
			result := NBIoTRLFReportContainer(v)
			return &result, nil
		}
	case "CellActivationRequest-IEs":
		switch ieId {
		case 57: // id-ServedCellsToActivate -> ServedCellsToActivate (SEQUENCE_OF)
			v, err := UnmarshalAPERServedCellsToActivateFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedCellsToActivate (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CellActivationResponse-IEs":
		switch ieId {
		case 58: // id-ActivatedCellList -> ActivatedCellList (SEQUENCE_OF)
			v, err := UnmarshalAPERActivatedCellListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ActivatedCellList (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CellActivationFailure-IEs":
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
	case "X2Release-IEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENBID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENBID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "X2APMessageTransfer-IEs":
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
	case "SeNBAdditionRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
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
		case 116: // id-ServingPLMN -> PLMNIdentity (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PLMNIdentity (%d): %w", ieId, err)
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
		case 112: // id-SeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 104: // id-ExpectedUEBehaviour -> ExpectedUEBehaviour
			var v ExpectedUEBehaviour
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ExpectedUEBehaviour (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "E-RABs-ToBeAdded-ItemIEs":
		switch ieId {
		case 118: // id-E-RABs-ToBeAdded-Item -> ERABsToBeAddedItem
			var v ERABsToBeAddedItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeAddedItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SeNBAdditionRequestAcknowledge-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 120: // id-E-RABs-Admitted-ToBeAdded-List -> ERABsAdmittedToBeAddedList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeAddedList (%d): %w", ieId, err)
			}
			return &v, nil
		case 3: // id-E-RABs-NotAdmitted-List -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 163: // id-Tunnel-Information-for-BBF -> TunnelInformation
			var v TunnelInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TunnelInformation (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-Admitted-ToBeAdded-ItemIEs":
		switch ieId {
		case 121: // id-E-RABs-Admitted-ToBeAdded-Item -> ERABsAdmittedToBeAddedItem
			var v ERABsAdmittedToBeAddedItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeAddedItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SeNBAdditionRequestReject-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "SeNBReconfigurationComplete-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 123: // id-ResponseInformationSeNBReconfComp -> ResponseInformationSeNBReconfComp
			var v ResponseInformationSeNBReconfComp
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ResponseInformationSeNBReconfComp (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "SeNBModificationRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
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
		case 116: // id-ServingPLMN -> PLMNIdentity (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PLMNIdentity (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "E-RABs-ToBeAdded-ModReqItemIEs":
		switch ieId {
		case 125: // id-E-RABs-ToBeAdded-ModReqItem -> ERABsToBeAddedModReqItem
			var v ERABsToBeAddedModReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeAddedModReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-ToBeModified-ModReqItemIEs":
		switch ieId {
		case 126: // id-E-RABs-ToBeModified-ModReqItem -> ERABsToBeModifiedModReqItem
			var v ERABsToBeModifiedModReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeModifiedModReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-ToBeReleased-ModReqItemIEs":
		switch ieId {
		case 127: // id-E-RABs-ToBeReleased-ModReqItem -> ERABsToBeReleasedModReqItem
			var v ERABsToBeReleasedModReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedModReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SeNBModificationRequestAcknowledge-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
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
		case 3: // id-E-RABs-NotAdmitted-List -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "E-RABs-Admitted-ToBeAdded-ModAckItemIEs":
		switch ieId {
		case 131: // id-E-RABs-Admitted-ToBeAdded-ModAckItem -> ERABsAdmittedToBeAddedModAckItem
			var v ERABsAdmittedToBeAddedModAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeAddedModAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-Admitted-ToBeModified-ModAckItemIEs":
		switch ieId {
		case 132: // id-E-RABs-Admitted-ToBeModified-ModAckItem -> ERABsAdmittedToBeModifiedModAckItem
			var v ERABsAdmittedToBeModifiedModAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeModifiedModAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-Admitted-ToBeReleased-ModAckItemIEs":
		switch ieId {
		case 133: // id-E-RABs-Admitted-ToBeReleased-ModAckItem -> ERABsAdmittedToReleasedModAckItem
			var v ERABsAdmittedToReleasedModAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToReleasedModAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SeNBModificationRequestReject-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "SeNBModificationRequired-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "E-RABs-ToBeReleased-ModReqdItemIEs":
		switch ieId {
		case 135: // id-E-RABs-ToBeReleased-ModReqdItem -> ERABsToBeReleasedModReqdItem
			var v ERABsToBeReleasedModReqdItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedModReqdItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SeNBModificationConfirm-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "SeNBModificationRefuse-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "SeNBReleaseRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
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
		case 154: // id-UE-ContextKeptIndicator -> UEContextKeptIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEContextKeptIndicator (%d): %w", ieId, err)
			}
			result := UEContextKeptIndicator(v)
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 181: // id-MakeBeforeBreakIndicator -> MakeBeforeBreakIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MakeBeforeBreakIndicator (%d): %w", ieId, err)
			}
			result := MakeBeforeBreakIndicator(v)
			return &result, nil
		}
	case "E-RABs-ToBeReleased-RelReqItemIEs":
		switch ieId {
		case 138: // id-E-RABs-ToBeReleased-RelReqItem -> ERABsToBeReleasedRelReqItem
			var v ERABsToBeReleasedRelReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedRelReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SeNBReleaseRequired-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "SeNBReleaseConfirm-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "E-RABs-ToBeReleased-RelConfItemIEs":
		switch ieId {
		case 140: // id-E-RABs-ToBeReleased-RelConfItem -> ERABsToBeReleasedRelConfItem
			var v ERABsToBeReleasedRelConfItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedRelConfItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SeNBCounterCheckRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 112: // id-SeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 141: // id-E-RABs-SubjectToCounterCheck-List -> ERABsSubjectToCounterCheckList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsSubjectToCounterCheckList (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "E-RABs-SubjectToCounterCheckItemIEs":
		switch ieId {
		case 142: // id-E-RABs-SubjectToCounterCheckItem -> ERABsSubjectToCounterCheckItem
			var v ERABsSubjectToCounterCheckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsSubjectToCounterCheckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "X2RemovalRequest-IEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENBID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENBID (%d): %w", ieId, err)
			}
			return &v, nil
		case 169: // id-X2RemovalThreshold -> X2BenefitValue (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("8"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE X2BenefitValue (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "X2RemovalResponse-IEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENBID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENBID (%d): %w", ieId, err)
			}
			return &v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "X2RemovalFailure-IEs":
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
	case "RetrieveUEContextRequest-IEs":
		switch ieId {
		case 9: // id-New-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 158: // id-SeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 172: // id-resumeID -> ResumeID
			var v ResumeID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ResumeID (%d): %w", ieId, err)
			}
			return &v, nil
		case 51: // id-ShortMAC-I -> ShortMACI (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ShortMACI (%d): %w", ieId, err)
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
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("503"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PCI (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "RetrieveUEContextResponse-IEs":
		switch ieId {
		case 9: // id-New-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 10: // id-Old-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
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
		case 98: // id-Masked-IMEISV -> MaskedIMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MaskedIMEISV (%d): %w", ieId, err)
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
		case 309: // id-Subscription-Based-UE-DifferentiationInfo -> SubscriptionBasedUEDifferentiationInfo
			var v SubscriptionBasedUEDifferentiationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE SubscriptionBasedUEDifferentiationInfo (%d): %w", ieId, err)
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
	case "E-RABs-ToBeSetupRetrieve-ItemIEs":
		switch ieId {
		case 174: // id-E-RABs-ToBeSetupRetrieve-Item -> ERABsToBeSetupRetrieveItem
			var v ERABsToBeSetupRetrieveItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeSetupRetrieveItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "RetrieveUEContextFailure-IEs":
		switch ieId {
		case 9: // id-New-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
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
	case "SgNBAdditionRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
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
		case 269: // id-SelectedPLMN -> PLMNIdentity (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PLMNIdentity (%d): %w", ieId, err)
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
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 104: // id-ExpectedUEBehaviour -> ExpectedUEBehaviour
			var v ExpectedUEBehaviour
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ExpectedUEBehaviour (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
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
		case 278: // id-SGNB-Addition-Trigger-Ind -> SGNBAdditionTriggerInd (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SGNBAdditionTriggerInd (%d): %w", ieId, err)
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
		case 98: // id-Masked-IMEISV -> MaskedIMEISV (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 64, 64, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MaskedIMEISV (%d): %w", ieId, err)
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
		case 359: // id-UEContextReferenceatSourceNGRAN -> RANUENGAPID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RANUENGAPID (%d): %w", ieId, err)
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
		case 89: // id-ManagementBasedMDTPLMNList -> MDTPLMNList (SEQUENCE_OF)
			v, err := UnmarshalAPERMDTPLMNListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MDTPLMNList (%d): %w", ieId, err)
			}
			return &v, nil
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
		case 411: // id-sourceNG-RAN-node-id -> GlobalRANNODEID
			var v GlobalRANNODEID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalRANNODEID (%d): %w", ieId, err)
			}
			return &v, nil
		case 15: // id-UE-HistoryInformation -> UEHistoryInformation (SEQUENCE_OF)
			v, err := UnmarshalAPERUEHistoryInformationFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEHistoryInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 105: // id-UE-HistoryInformationFromTheUE -> UEHistoryInformationFromTheUE (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEHistoryInformationFromTheUE (%d): %w", ieId, err)
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
		case 420: // id-CHOinformation-AddReq -> CHOinformationAddReq
			var v CHOinformationAddReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CHOinformationAddReq (%d): %w", ieId, err)
			}
			return &v, nil
		case 423: // id-SCGActivationRequest -> SCGActivationRequest (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGActivationRequest (%d): %w", ieId, err)
			}
			result := SCGActivationRequest(v)
			return &result, nil
		case 424: // id-CPAinformation-REQ -> CPAinformationREQ
			var v CPAinformationREQ
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPAinformationREQ (%d): %w", ieId, err)
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
	case "E-RABs-ToBeAdded-SgNBAddReq-ItemIEs":
		switch ieId {
		case 209: // id-E-RABs-ToBeAdded-SgNBAddReq-Item -> ERABsToBeAddedSgNBAddReqItem
			var v ERABsToBeAddedSgNBAddReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeAddedSgNBAddReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBAdditionRequestAcknowledge-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 210: // id-E-RABs-Admitted-ToBeAdded-SgNBAddReqAckList -> ERABsAdmittedToBeAddedSgNBAddReqAckList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeAddedSgNBAddReqAckList (%d): %w", ieId, err)
			}
			return &v, nil
		case 3: // id-E-RABs-NotAdmitted-List -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
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
		case 272: // id-RRCConfigIndication -> RRCConfigInd (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RRCConfigInd (%d): %w", ieId, err)
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
		case 425: // id-CPAinformation-REQ-ACK -> CPAinformationREQACK
			var v CPAinformationREQACK
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPAinformationREQACK (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-ItemIEs":
		switch ieId {
		case 213: // id-E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item -> ERABsAdmittedToBeAddedSgNBAddReqAckItem
			var v ERABsAdmittedToBeAddedSgNBAddReqAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeAddedSgNBAddReqAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBAdditionRequestReject-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "SgNBReconfigurationComplete-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 214: // id-ResponseInformationSgNBReconfComp -> ResponseInformationSgNBReconfComp
			var v ResponseInformationSgNBReconfComp
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ResponseInformationSgNBReconfComp (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "SgNBModificationRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 269: // id-SelectedPLMN -> PLMNIdentity (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PLMNIdentity (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
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
		case 105: // id-UE-HistoryInformationFromTheUE -> UEHistoryInformationFromTheUE (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEHistoryInformationFromTheUE (%d): %w", ieId, err)
			}
			result := UEHistoryInformationFromTheUE(v)
			return &result, nil
		case 421: // id-CHOinformation-ModReq -> CHOinformationModReq
			var v CHOinformationModReq
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CHOinformationModReq (%d): %w", ieId, err)
			}
			return &v, nil
		case 423: // id-SCGActivationRequest -> SCGActivationRequest (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGActivationRequest (%d): %w", ieId, err)
			}
			result := SCGActivationRequest(v)
			return &result, nil
		case 426: // id-CPAinformation-MOD -> CPAinformationMOD
			var v CPAinformationMOD
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPAinformationMOD (%d): %w", ieId, err)
			}
			return &v, nil
		case 432: // id-CPCupdate-MOD -> CPCupdateMOD
			var v CPCupdateMOD
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPCupdateMOD (%d): %w", ieId, err)
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
	case "E-RABs-ToBeAdded-SgNBModReq-ItemIEs":
		switch ieId {
		case 216: // id-E-RABs-ToBeAdded-SgNBModReq-Item -> ERABsToBeAddedSgNBModReqItem
			var v ERABsToBeAddedSgNBModReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeAddedSgNBModReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-ToBeModified-SgNBModReq-ItemIEs":
		switch ieId {
		case 217: // id-E-RABs-ToBeModified-SgNBModReq-Item -> ERABsToBeModifiedSgNBModReqItem
			var v ERABsToBeModifiedSgNBModReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeModifiedSgNBModReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-ToBeReleased-SgNBModReq-ItemIEs":
		switch ieId {
		case 218: // id-E-RABs-ToBeReleased-SgNBModReq-Item -> ERABsToBeReleasedSgNBModReqItem
			var v ERABsToBeReleasedSgNBModReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBModReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBModificationRequestAcknowledge-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 3: // id-E-RABs-NotAdmitted-List -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
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
		case 272: // id-RRCConfigIndication -> RRCConfigInd (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RRCConfigInd (%d): %w", ieId, err)
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
		case 415: // id-SCG-UE-HistoryInformation -> SCGUEHistoryInformation (SEQUENCE_OF)
			v, err := UnmarshalAPERSCGUEHistoryInformationFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGUEHistoryInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 422: // id-SCGActivationStatus -> SCGActivationStatus (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGActivationStatus (%d): %w", ieId, err)
			}
			result := SCGActivationStatus(v)
			return &result, nil
		case 427: // id-CPAinformation-MOD-ACK -> CPAinformationMODACK
			var v CPAinformationMODACK
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPAinformationMODACK (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-Admitted-ToBeAdded-SgNBModAck-ItemIEs":
		switch ieId {
		case 222: // id-E-RABs-Admitted-ToBeAdded-SgNBModAck-Item -> ERABsAdmittedToBeAddedSgNBModAckItem
			var v ERABsAdmittedToBeAddedSgNBModAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeAddedSgNBModAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-Admitted-ToBeModified-SgNBModAck-ItemIEs":
		switch ieId {
		case 223: // id-E-RABs-Admitted-ToBeModified-SgNBModAck-Item -> ERABsAdmittedToBeModifiedSgNBModAckItem
			var v ERABsAdmittedToBeModifiedSgNBModAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeModifiedSgNBModAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-Admitted-ToBeReleased-SgNBModAck-ItemIEs":
		switch ieId {
		case 224: // id-E-RABs-Admitted-ToBeReleased-SgNBModAck-Item -> ERABsAdmittedToReleasedSgNBModAckItem
			var v ERABsAdmittedToReleasedSgNBModAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToReleasedSgNBModAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBModificationRequestReject-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "SgNBModificationRequired-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
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
		case 272: // id-RRCConfigIndication -> RRCConfigInd (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RRCConfigInd (%d): %w", ieId, err)
			}
			result := RRCConfigInd(v)
			return &result, nil
		case 331: // id-LocationInformationSgNB -> LocationInformationSgNB
			var v LocationInformationSgNB
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE LocationInformationSgNB (%d): %w", ieId, err)
			}
			return &v, nil
		case 415: // id-SCG-UE-HistoryInformation -> SCGUEHistoryInformation (SEQUENCE_OF)
			v, err := UnmarshalAPERSCGUEHistoryInformationFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGUEHistoryInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 423: // id-SCGActivationRequest -> SCGActivationRequest (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGActivationRequest (%d): %w", ieId, err)
			}
			result := SCGActivationRequest(v)
			return &result, nil
		case 428: // id-CPACinformation-REQD -> CPACinformationREQD
			var v CPACinformationREQD
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPACinformationREQD (%d): %w", ieId, err)
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
	case "E-RABs-ToBeReleased-SgNBModReqd-ItemIEs":
		switch ieId {
		case 227: // id-E-RABs-ToBeReleased-SgNBModReqd-Item -> ERABsToBeReleasedSgNBModReqdItem
			var v ERABsToBeReleasedSgNBModReqdItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBModReqdItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-ToBeModified-SgNBModReqd-ItemIEs":
		switch ieId {
		case 228: // id-E-RABs-ToBeModified-SgNBModReqd-Item -> ERABsToBeModifiedSgNBModReqdItem
			var v ERABsToBeModifiedSgNBModReqdItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeModifiedSgNBModReqdItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBModificationConfirm-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 257: // id-MeNBResourceCoordinationInformation -> MeNBResourceCoordinationInformation
			var v MeNBResourceCoordinationInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE MeNBResourceCoordinationInformation (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-AdmittedToBeModified-SgNBModConf-ItemIEs":
		switch ieId {
		case 295: // id-E-RABs-AdmittedToBeModified-SgNBModConf-Item -> ERABsAdmittedToBeModifiedSgNBModConfItem
			var v ERABsAdmittedToBeModifiedSgNBModConfItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeModifiedSgNBModConfItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBModificationRefuse-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "SgNBReleaseRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 154: // id-UE-ContextKeptIndicator -> UEContextKeptIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEContextKeptIndicator (%d): %w", ieId, err)
			}
			result := UEContextKeptIndicator(v)
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 206: // id-MeNBtoSgNBContainer -> MeNBtoSgNBContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeNBtoSgNBContainer (%d): %w", ieId, err)
			}
			result := MeNBtoSgNBContainer(v)
			return &result, nil
		case 339: // id-ERABs-transferred-to-MeNB -> ERABList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-ToBeReleased-SgNBRelReq-ItemIEs":
		switch ieId {
		case 232: // id-E-RABs-ToBeReleased-SgNBRelReq-Item -> ERABsToBeReleasedSgNBRelReqItem
			var v ERABsToBeReleasedSgNBRelReqItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBRelReqItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBReleaseRequestAcknowledge-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 318: // id-E-RABs-Admitted-ToBeReleased-SgNBRelReqAckList -> ERABsAdmittedToBeReleasedSgNBRelReqAckList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeReleasedSgNBRelReqAckList (%d): %w", ieId, err)
			}
			return &v, nil
		case 415: // id-SCG-UE-HistoryInformation -> SCGUEHistoryInformation (SEQUENCE_OF)
			v, err := UnmarshalAPERSCGUEHistoryInformationFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGUEHistoryInformation (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-Admitted-ToBeReleased-SgNBRelReqAck-ItemIEs":
		switch ieId {
		case 319: // id-E-RABs-Admitted-ToBeReleased-SgNBRelReqAck-Item -> ERABsAdmittedToBeReleasedSgNBRelReqAckItem
			var v ERABsAdmittedToBeReleasedSgNBRelReqAckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsAdmittedToBeReleasedSgNBRelReqAckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBReleaseRequestReject-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "SgNBReleaseRequired-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
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
		case 415: // id-SCG-UE-HistoryInformation -> SCGUEHistoryInformation (SEQUENCE_OF)
			v, err := UnmarshalAPERSCGUEHistoryInformationFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGUEHistoryInformation (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-ToBeReleased-SgNBRelReqd-ItemIEs":
		switch ieId {
		case 321: // id-E-RABs-ToBeReleased-SgNBRelReqd-Item -> ERABsToBeReleasedSgNBRelReqdItem
			var v ERABsToBeReleasedSgNBRelReqdItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBRelReqdItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBReleaseConfirm-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "E-RABs-ToBeReleased-SgNBRelConf-ItemIEs":
		switch ieId {
		case 234: // id-E-RABs-ToBeReleased-SgNBRelConf-Item -> ERABsToBeReleasedSgNBRelConfItem
			var v ERABsToBeReleasedSgNBRelConfItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBRelConfItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBCounterCheckRequest-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 235: // id-E-RABs-SubjectToSgNBCounterCheck-List -> ERABsSubjectToSgNBCounterCheckList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsSubjectToSgNBCounterCheckList (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "E-RABs-SubjectToSgNBCounterCheck-ItemIEs":
		switch ieId {
		case 236: // id-E-RABs-SubjectToSgNBCounterCheck-Item -> ERABsSubjectToSgNBCounterCheckItem
			var v ERABsSubjectToSgNBCounterCheckItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsSubjectToSgNBCounterCheckItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBChangeRequired-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 239: // id-Target-SgNB-ID -> GlobalGNBID
			var v GlobalGNBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalGNBID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 415: // id-SCG-UE-HistoryInformation -> SCGUEHistoryInformation (SEQUENCE_OF)
			v, err := UnmarshalAPERSCGUEHistoryInformationFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGUEHistoryInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 429: // id-CPCinformation-REQD -> CPCinformationREQD
			var v CPCinformationREQD
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPCinformationREQD (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "AccessAndMobilityIndication-IEs":
		switch ieId {
		case 414: // id-NRRAReport -> NRRAReport (SEQUENCE_OF)
			v, err := UnmarshalAPERNRRAReportFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE NRRAReport (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SgNBChangeConfirm-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 430: // id-CPCinformation-CONF -> CPCinformationCONF
			var v CPCinformationCONF
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPCinformationCONF (%d): %w", ieId, err)
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
	case "E-RABs-ToBeReleased-SgNBChaConf-ItemIEs":
		switch ieId {
		case 230: // id-E-RABs-ToBeReleased-SgNBChaConf-Item -> ERABsToBeReleasedSgNBChaConfItem
			var v ERABsToBeReleasedSgNBChaConfItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsToBeReleasedSgNBChaConfItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "RRCTransfer-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
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
	case "SgNBChangeRefuse-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ENDCX2SetupRequest-IEs":
		switch ieId {
		case 244: // id-InitiatingNodeType-EndcX2Setup -> InitiatingNodeTypeEndcX2Setup
			var v InitiatingNodeTypeEndcX2Setup
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE InitiatingNodeTypeEndcX2Setup (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		case 352: // id-TNLConfigurationInfo -> TNLConfigurationInfo
			var v TNLConfigurationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TNLConfigurationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENB-ENDCX2SetupReqIEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENBID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENBID (%d): %w", ieId, err)
			}
			return &v, nil
		case 250: // id-ServedEUTRAcellsENDCX2ManagementList -> ServedEUTRAcellsENDCX2ManagementList (SEQUENCE_OF)
			v, err := UnmarshalAPERServedEUTRAcellsENDCX2ManagementListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedEUTRAcellsENDCX2ManagementList (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		case 351: // id-CellandCapacityAssistInfo -> CellandCapacityAssistInfo
			var v CellandCapacityAssistInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellandCapacityAssistInfo (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "En-gNB-ENDCX2SetupReqIEs":
		switch ieId {
		case 252: // id-Globalen-gNB-ID -> GlobalGNBID
			var v GlobalGNBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalGNBID (%d): %w", ieId, err)
			}
			return &v, nil
		case 253: // id-ServedNRcellsENDCX2ManagementList -> ServedNRcellsENDCX2ManagementList (SEQUENCE_OF)
			v, err := UnmarshalAPERServedNRcellsENDCX2ManagementListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedNRcellsENDCX2ManagementList (%d): %w", ieId, err)
			}
			return &v, nil
		case 348: // id-PartialListIndicator -> PartialListIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PartialListIndicator (%d): %w", ieId, err)
			}
			result := PartialListIndicator(v)
			return &result, nil
		}
	case "ENDCX2SetupResponse-IEs":
		switch ieId {
		case 246: // id-RespondingNodeType-EndcX2Setup -> RespondingNodeTypeEndcX2Setup
			var v RespondingNodeTypeEndcX2Setup
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RespondingNodeTypeEndcX2Setup (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		case 352: // id-TNLConfigurationInfo -> TNLConfigurationInfo
			var v TNLConfigurationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TNLConfigurationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENB-ENDCX2SetupReqAckIEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENBID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENBID (%d): %w", ieId, err)
			}
			return &v, nil
		case 250: // id-ServedEUTRAcellsENDCX2ManagementList -> ServedEUTRAcellsENDCX2ManagementList (SEQUENCE_OF)
			v, err := UnmarshalAPERServedEUTRAcellsENDCX2ManagementListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedEUTRAcellsENDCX2ManagementList (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		case 351: // id-CellandCapacityAssistInfo -> CellandCapacityAssistInfo
			var v CellandCapacityAssistInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellandCapacityAssistInfo (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "En-gNB-ENDCX2SetupReqAckIEs":
		switch ieId {
		case 252: // id-Globalen-gNB-ID -> GlobalGNBID
			var v GlobalGNBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalGNBID (%d): %w", ieId, err)
			}
			return &v, nil
		case 253: // id-ServedNRcellsENDCX2ManagementList -> ServedNRcellsENDCX2ManagementList (SEQUENCE_OF)
			v, err := UnmarshalAPERServedNRcellsENDCX2ManagementListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedNRcellsENDCX2ManagementList (%d): %w", ieId, err)
			}
			return &v, nil
		case 348: // id-PartialListIndicator -> PartialListIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE PartialListIndicator (%d): %w", ieId, err)
			}
			result := PartialListIndicator(v)
			return &result, nil
		}
	case "ENDCX2SetupFailure-IEs":
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
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		case 350: // id-MessageOversizeNotification -> MessageOversizeNotification
			var v MessageOversizeNotification
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE MessageOversizeNotification (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENDCConfigurationUpdate-IEs":
		switch ieId {
		case 245: // id-InitiatingNodeType-EndcConfigUpdate -> InitiatingNodeTypeEndcConfigUpdate
			var v InitiatingNodeTypeEndcConfigUpdate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE InitiatingNodeTypeEndcConfigUpdate (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		case 352: // id-TNLConfigurationInfo -> TNLConfigurationInfo
			var v TNLConfigurationInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TNLConfigurationInfo (%d): %w", ieId, err)
			}
			return &v, nil
		case 353: // id-TNLA-To-Add-List -> TNLAToAddList (SEQUENCE_OF)
			v, err := UnmarshalAPERTNLAToAddListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TNLAToAddList (%d): %w", ieId, err)
			}
			return &v, nil
		case 354: // id-TNLA-To-Update-List -> TNLAToUpdateList (SEQUENCE_OF)
			v, err := UnmarshalAPERTNLAToUpdateListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TNLAToUpdateList (%d): %w", ieId, err)
			}
			return &v, nil
		case 355: // id-TNLA-To-Remove-List -> TNLAToRemoveList (SEQUENCE_OF)
			v, err := UnmarshalAPERTNLAToRemoveListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TNLAToRemoveList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENB-ENDCConfigUpdateIEs":
		switch ieId {
		case 251: // id-CellAssistanceInformation -> CellAssistanceInformation
			var v CellAssistanceInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellAssistanceInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 250: // id-ServedEUTRAcellsENDCX2ManagementList -> ServedEUTRAcellsENDCX2ManagementList (SEQUENCE_OF)
			v, err := UnmarshalAPERServedEUTRAcellsENDCX2ManagementListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedEUTRAcellsENDCX2ManagementList (%d): %w", ieId, err)
			}
			return &v, nil
		case 259: // id-ServedEUTRAcellsToModifyListENDCConfUpd -> ServedEUTRAcellsToModifyListENDCConfUpd (SEQUENCE_OF)
			v, err := UnmarshalAPERServedEUTRAcellsToModifyListENDCConfUpdFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedEUTRAcellsToModifyListENDCConfUpd (%d): %w", ieId, err)
			}
			return &v, nil
		case 260: // id-ServedEUTRAcellsToDeleteListENDCConfUpd -> ServedEUTRAcellsToDeleteListENDCConfUpd (SEQUENCE_OF)
			v, err := UnmarshalAPERServedEUTRAcellsToDeleteListENDCConfUpdFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedEUTRAcellsToDeleteListENDCConfUpd (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "En-gNB-ENDCConfigUpdateIEs":
		switch ieId {
		case 253: // id-ServedNRcellsENDCX2ManagementList -> ServedNRcellsENDCX2ManagementList (SEQUENCE_OF)
			v, err := UnmarshalAPERServedNRcellsENDCX2ManagementListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedNRcellsENDCX2ManagementList (%d): %w", ieId, err)
			}
			return &v, nil
		case 261: // id-ServedNRcellsToModifyListENDCConfUpd -> ServedNRcellsToModifyENDCConfUpdList (SEQUENCE_OF)
			v, err := UnmarshalAPERServedNRcellsToModifyENDCConfUpdListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedNRcellsToModifyENDCConfUpdList (%d): %w", ieId, err)
			}
			return &v, nil
		case 262: // id-ServedNRcellsToDeleteListENDCConfUpd -> ServedNRcellsToDeleteENDCConfUpdList (SEQUENCE_OF)
			v, err := UnmarshalAPERServedNRcellsToDeleteENDCConfUpdListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedNRcellsToDeleteENDCConfUpdList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENDCConfigurationUpdateAcknowledge-IEs":
		switch ieId {
		case 247: // id-RespondingNodeType-EndcConfigUpdate -> RespondingNodeTypeEndcConfigUpdate
			var v RespondingNodeTypeEndcConfigUpdate
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RespondingNodeTypeEndcConfigUpdate (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
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
		case 356: // id-TNLA-Setup-List -> TNLASetupList (SEQUENCE_OF)
			v, err := UnmarshalAPERTNLASetupListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TNLASetupList (%d): %w", ieId, err)
			}
			return &v, nil
		case 357: // id-TNLA-Failed-To-Setup-List -> TNLAFailedToSetupList (SEQUENCE_OF)
			v, err := UnmarshalAPERTNLAFailedToSetupListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TNLAFailedToSetupList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "En-gNB-ENDCConfigUpdateAckIEs":
		switch ieId {
		case 253: // id-ServedNRcellsENDCX2ManagementList -> ServedNRcellsENDCX2ManagementList (SEQUENCE_OF)
			v, err := UnmarshalAPERServedNRcellsENDCX2ManagementListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedNRcellsENDCX2ManagementList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENDCConfigurationUpdateFailure-IEs":
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
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ENDCCellActivationRequest-IEs":
		switch ieId {
		case 267: // id-ServedNRCellsToActivate -> ServedNRCellsToActivate (SEQUENCE_OF)
			v, err := UnmarshalAPERServedNRCellsToActivateFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ServedNRCellsToActivate (%d): %w", ieId, err)
			}
			return &v, nil
		case 256: // id-ActivationID -> ActivationID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(255), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ActivationID (%d): %w", ieId, err)
			}
			result := ActivationID(v)
			return &result, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ENDCCellActivationResponse-IEs":
		switch ieId {
		case 268: // id-ActivatedNRCellList -> ActivatedNRCellList (SEQUENCE_OF)
			v, err := UnmarshalAPERActivatedNRCellListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ActivatedNRCellList (%d): %w", ieId, err)
			}
			return &v, nil
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
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ENDCCellActivationFailure-IEs":
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
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ENDCResourceStatusRequest-IEs":
		switch ieId {
		case 383: // id-E-UTRAN-Node1-Measurement-ID -> MeasurementIDENDC (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementIDENDC (%d): %w", ieId, err)
			}
			return v, nil
		case 384: // id-E-UTRAN-Node2-Measurement-ID -> MeasurementIDENDC (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementIDENDC (%d): %w", ieId, err)
			}
			return v, nil
		case 28: // id-Registration-Request -> RegistrationRequestENDC (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RegistrationRequestENDC (%d): %w", ieId, err)
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
		case 38: // id-ReportCharacteristics -> ReportCharacteristicsENDC (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 32, 32, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ReportCharacteristicsENDC (%d): %w", ieId, err)
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
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		case 403: // id-CellToReport-E-UTRA-ENDC -> CellToReportEUTRAENDCList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellToReportEUTRAENDCList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CellToReport-NR-ENDC-ItemIEs":
		switch ieId {
		case 392: // id-CellToReport-NR-ENDC-Item -> CellToReportNRENDCItem
			var v CellToReportNRENDCItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellToReportNRENDCItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CellToReport-E-UTRA-ENDC-Item-IEs":
		switch ieId {
		case 404: // id-CellToReport-E-UTRA-ENDC-Item -> CellToReportEUTRAENDCItem
			var v CellToReportEUTRAENDCItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellToReportEUTRAENDCItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENDCResourceStatusResponse-IEs":
		switch ieId {
		case 383: // id-E-UTRAN-Node1-Measurement-ID -> MeasurementIDENDC (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementIDENDC (%d): %w", ieId, err)
			}
			return v, nil
		case 384: // id-E-UTRAN-Node2-Measurement-ID -> MeasurementIDENDC (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementIDENDC (%d): %w", ieId, err)
			}
			return v, nil
		case 17: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ENDCResourceStatusFailure-IEs":
		switch ieId {
		case 383: // id-E-UTRAN-Node1-Measurement-ID -> MeasurementIDENDC (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementIDENDC (%d): %w", ieId, err)
			}
			return v, nil
		case 384: // id-E-UTRAN-Node2-Measurement-ID -> MeasurementIDENDC (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementIDENDC (%d): %w", ieId, err)
			}
			return v, nil
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
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ENDCResourceStatusUpdate-IEs":
		switch ieId {
		case 383: // id-E-UTRAN-Node1-Measurement-ID -> MeasurementIDENDC (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementIDENDC (%d): %w", ieId, err)
			}
			return v, nil
		case 384: // id-E-UTRAN-Node2-Measurement-ID -> MeasurementIDENDC (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementIDENDC (%d): %w", ieId, err)
			}
			return v, nil
		case 393: // id-CellMeasurementResult-NR-ENDC -> CellMeasurementResultNRENDCList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 16384)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellMeasurementResultNRENDCList (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		case 401: // id-CellMeasurementResult-E-UTRA-ENDC -> CellMeasurementResultEUTRAENDCList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellMeasurementResultEUTRAENDCList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CellMeasurementResult-NR-ENDC-ItemIEs":
		switch ieId {
		case 394: // id-CellMeasurementResult-NR-ENDC-Item -> CellMeasurementResultNRENDCItem
			var v CellMeasurementResultNRENDCItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellMeasurementResultNRENDCItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "CellMeasurementResult-E-UTRA-ENDC-ItemIEs":
		switch ieId {
		case 402: // id-CellMeasurementResult-E-UTRA-ENDC-Item -> CellMeasurementResultEUTRAENDCItem
			var v CellMeasurementResultEUTRAENDCItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CellMeasurementResultEUTRAENDCItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SecondaryRATDataUsageReport-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 265: // id-SecondaryRATUsageReportList -> SecondaryRATUsageReportList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SecondaryRATUsageReportList (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "SgNBActivityNotification-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 297: // id-ERABActivityNotifyItemList -> ERABActivityNotifyItemList (SEQUENCE_OF)
			v, err := UnmarshalAPERERABActivityNotifyItemListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABActivityNotifyItemList (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ENDCPartialResetRequired-IEs":
		switch ieId {
		case 270: // id-UEs-ToBeReset -> UEsToBeResetList (SEQUENCE_OF)
			v, err := UnmarshalAPERUEsToBeResetListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEsToBeResetList (%d): %w", ieId, err)
			}
			return &v, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ENDCPartialResetConfirm-IEs":
		switch ieId {
		case 271: // id-UEs-Admitted-ToBeReset -> UEsToBeResetList (SEQUENCE_OF)
			v, err := UnmarshalAPERUEsToBeResetListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEsToBeResetList (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "EUTRANRCellResourceCoordinationRequest-IEs":
		switch ieId {
		case 285: // id-InitiatingNodeType-EutranrCellResourceCoordination -> InitiatingNodeTypeEutranrCellResourceCoordination
			var v InitiatingNodeTypeEutranrCellResourceCoordination
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE InitiatingNodeTypeEutranrCellResourceCoordination (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ENB-EUTRA-NRCellResourceCoordinationReqIEs":
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
		case 289: // id-ListofEUTRACellsinEUTRACoordinationReq -> ListofEUTRACellsinEUTRACoordinationReq (SEQUENCE_OF)
			v, err := UnmarshalAPERListofEUTRACellsinEUTRACoordinationReqFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ListofEUTRACellsinEUTRACoordinationReq (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "En-gNB-EUTRA-NRCellResourceCoordinationReqIEs":
		switch ieId {
		case 287: // id-DataTrafficResourceIndication -> DataTrafficResourceIndication
			var v DataTrafficResourceIndication
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE DataTrafficResourceIndication (%d): %w", ieId, err)
			}
			return &v, nil
		case 291: // id-ListofEUTRACellsinNRCoordinationReq -> ListofEUTRACellsinNRCoordinationReq (SEQUENCE_OF)
			v, err := UnmarshalAPERListofEUTRACellsinNRCoordinationReqFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ListofEUTRACellsinNRCoordinationReq (%d): %w", ieId, err)
			}
			return &v, nil
		case 288: // id-SpectrumSharingGroupID -> SpectrumSharingGroupID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(1), int64Ptr(256), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SpectrumSharingGroupID (%d): %w", ieId, err)
			}
			result := SpectrumSharingGroupID(v)
			return &result, nil
		case 292: // id-ListofNRCellsinNRCoordinationReq -> ListofNRCellsinNRCoordinationReq (SEQUENCE_OF)
			v, err := UnmarshalAPERListofNRCellsinNRCoordinationReqFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ListofNRCellsinNRCoordinationReq (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "EUTRANRCellResourceCoordinationResponse-IEs":
		switch ieId {
		case 286: // id-RespondingNodeType-EutranrCellResourceCoordination -> RespondingNodeTypeEutranrCellResourceCoordination
			var v RespondingNodeTypeEutranrCellResourceCoordination
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RespondingNodeTypeEutranrCellResourceCoordination (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ENB-EUTRA-NRCellResourceCoordinationReqAckIEs":
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
		case 290: // id-ListofEUTRACellsinEUTRACoordinationResp -> ListofEUTRACellsinEUTRACoordinationResp (SEQUENCE_OF)
			v, err := UnmarshalAPERListofEUTRACellsinEUTRACoordinationRespFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ListofEUTRACellsinEUTRACoordinationResp (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "En-gNB-EUTRA-NRCellResourceCoordinationReqAckIEs":
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
		case 293: // id-ListofNRCellsinNRCoordinationResp -> ListofNRCellsinNRCoordinationResp (SEQUENCE_OF)
			v, err := UnmarshalAPERListofNRCellsinNRCoordinationRespFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ListofNRCellsinNRCoordinationResp (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENDCX2RemovalRequest-IEs":
		switch ieId {
		case 298: // id-InitiatingNodeType-EndcX2Removal -> InitiatingNodeTypeEndcX2Removal
			var v InitiatingNodeTypeEndcX2Removal
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE InitiatingNodeTypeEndcX2Removal (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ENB-ENDCX2RemovalReqIEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENBID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENBID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "En-gNB-ENDCX2RemovalReqIEs":
		switch ieId {
		case 252: // id-Globalen-gNB-ID -> GlobalGNBID
			var v GlobalGNBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalGNBID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENDCX2RemovalResponse-IEs":
		switch ieId {
		case 299: // id-RespondingNodeType-EndcX2Removal -> RespondingNodeTypeEndcX2Removal
			var v RespondingNodeTypeEndcX2Removal
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE RespondingNodeTypeEndcX2Removal (%d): %w", ieId, err)
			}
			return &v, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ENB-ENDCX2RemovalReqAckIEs":
		switch ieId {
		case 21: // id-GlobalENB-ID -> GlobalENBID
			var v GlobalENBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalENBID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "En-gNB-ENDCX2RemovalReqAckIEs":
		switch ieId {
		case 252: // id-Globalen-gNB-ID -> GlobalGNBID
			var v GlobalGNBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalGNBID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ENDCX2RemovalFailure-IEs":
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
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "DataForwardingAddressIndication-IEs":
		switch ieId {
		case 9: // id-New-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 155: // id-New-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 10: // id-Old-eNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 156: // id-Old-eNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 307: // id-E-RABs-DataForwardingAddress-List -> ERABsDataForwardingAddressList (SEQUENCE OF ProtocolIE-Field)
			v, err := decodeIEProtocolIEFieldListConstrained(bb, 1, 256)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ERABsDataForwardingAddressList (%d): %w", ieId, err)
			}
			return &v, nil
		case 368: // id-CHO-DC-Indicator -> CHODCIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CHODCIndicator (%d): %w", ieId, err)
			}
			result := CHODCIndicator(v)
			return &result, nil
		case 407: // id-CHO-DC-EarlyDataForwarding -> CHODCEarlyDataForwarding (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CHODCEarlyDataForwarding (%d): %w", ieId, err)
			}
			result := CHODCEarlyDataForwarding(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 431: // id-CPCinformation-NOTIFY -> CPCinformationNOTIFY
			var v CPCinformationNOTIFY
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE CPCinformationNOTIFY (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-RABs-DataForwardingAddress-ItemIEs":
		switch ieId {
		case 308: // id-E-RABs-DataForwardingAddress-Item -> ERABsDataForwardingAddressItem
			var v ERABsDataForwardingAddressItem
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE ERABsDataForwardingAddressItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "GNBStatusIndicationIEs":
		switch ieId {
		case 310: // id-GNBOverloadInformation -> GNBOverloadInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE GNBOverloadInformation (%d): %w", ieId, err)
			}
			result := GNBOverloadInformation(v)
			return &result, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "ENDCConfigurationTransfer-IEs":
		switch ieId {
		case 326: // id-endcSONConfigurationTransfer -> EndcSONConfigurationTransfer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE EndcSONConfigurationTransfer (%d): %w", ieId, err)
			}
			result := EndcSONConfigurationTransfer(v)
			return &result, nil
		case 335: // id-InterfaceInstanceIndication -> InterfaceInstanceIndication (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterfaceInstanceIndication (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "TraceStartIEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 13: // id-TraceActivation -> TraceActivation
			var v TraceActivation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE TraceActivation (%d): %w", ieId, err)
			}
			return &v, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "DeactivateTraceIEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "CellTrafficTraceIEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "F1CTrafficTransfer-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "UERadioCapabilityIDMappingRequestIEs":
		switch ieId {
		case 378: // id-UERadioCapabilityID -> UERadioCapabilityID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UERadioCapabilityID (%d): %w", ieId, err)
			}
			result := UERadioCapabilityID(v)
			return &result, nil
		}
	case "UERadioCapabilityIDMappingResponseIEs":
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
	case "CPC-cancel-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		case 157: // id-MeNB-UE-X2AP-ID-Extension -> UEX2APIDExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("4095"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APIDExtension (%d): %w", ieId, err)
			}
			return v, nil
		case 5: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 239: // id-Target-SgNB-ID -> GlobalGNBID
			var v GlobalGNBID
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding IE GlobalGNBID (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "RachIndication-IEs":
		switch ieId {
		case 447: // id-RaReportIndicationList -> RaReportIndicationList (SEQUENCE_OF)
			v, err := UnmarshalAPERRaReportIndicationListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding IE RaReportIndicationList (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "SCGFailureInformationReport-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
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
		case 452: // id-SCG-FailureReportContainer -> SCGFailureReportContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SCGFailureReportContainer (%d): %w", ieId, err)
			}
			result := SCGFailureReportContainer(v)
			return &result, nil
		case 453: // id-TimeSCG-Failure -> TimeSCGFailure (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(1023), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE TimeSCGFailure (%d): %w", ieId, err)
			}
			result := TimeSCGFailure(v)
			return &result, nil
		}
	case "SCGFailureTransfer-IEs":
		switch ieId {
		case 111: // id-MeNB-UE-X2AP-ID -> UEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4095), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE UEX2APID (%d): %w", ieId, err)
			}
			result := UEX2APID(v)
			return &result, nil
		case 207: // id-SgNB-UE-X2AP-ID -> SgNBUEX2APID (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(4294967295), false)
			if err != nil {
				return nil, fmt.Errorf("decoding IE SgNBUEX2APID (%d): %w", ieId, err)
			}
			result := SgNBUEX2APID(v)
			return &result, nil
		}
	}
	return nil, nil
}

// DecodeExtensionFieldValue decodes a known extension open value using its object-set context and ID.
// Returns the decoded typed value, or nil if the combination is unknown.
func DecodeExtensionFieldValue(objectSet string, extensionId int64, data []byte) (interface{}, error) {
	bb := per.NewBitBufferFromBytes(data)
	switch objectSet {
	case "CHOinformation-REQ-ExtIEs":
		switch extensionId {
		case 446: // id-CHOTimeBasedInformation -> CHOTimeBasedInformation
			var v CHOTimeBasedInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension CHOTimeBasedInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "E-RAB-Level-QoS-Parameters-ExtIEs":
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
	case "FDD-Info-ExtIEs":
		switch extensionId {
		case 95: // id-UL-EARFCNExtension -> EARFCNExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("65536"), runtime.MustParseBigIntDecimal("262143"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EARFCNExtension (%d): %w", extensionId, err)
			}
			return v, nil
		case 96: // id-DL-EARFCNExtension -> EARFCNExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("65536"), runtime.MustParseBigIntDecimal("262143"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EARFCNExtension (%d): %w", extensionId, err)
			}
			return v, nil
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
		case 282: // id-NRS-NSSS-PowerOffset -> NRSNSSSPowerOffset (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRSNSSSPowerOffset (%d): %w", extensionId, err)
			}
			result := NRSNSSSPowerOffset(v)
			return &result, nil
		case 283: // id-NSSS-NumOccasionDifferentPrecoder -> NSSSNumOccasionDifferentPrecoder (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NSSSNumOccasionDifferentPrecoder (%d): %w", extensionId, err)
			}
			result := NSSSNumOccasionDifferentPrecoder(v)
			return &result, nil
		}
	case "FDD-InfoNeighbourServedNRCell-Information-ExtIEs":
		switch extensionId {
		case 387: // id-ULCarrierList -> NRCarrierList (SEQUENCE_OF)
			v, err := UnmarshalAPERNRCarrierListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCarrierList (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "GBR-QosInformation-ExtIEs":
		switch extensionId {
		case 196: // id-extended-e-RAB-MaximumBitrateDL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("10000000001"), runtime.MustParseBigIntDecimal("4000000000000"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			return v, nil
		case 197: // id-extended-e-RAB-MaximumBitrateUL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("10000000001"), runtime.MustParseBigIntDecimal("4000000000000"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			return v, nil
		case 198: // id-extended-e-RAB-GuaranteedBitrateDL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("10000000001"), runtime.MustParseBigIntDecimal("4000000000000"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			return v, nil
		case 199: // id-extended-e-RAB-GuaranteedBitrateUL -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("10000000001"), runtime.MustParseBigIntDecimal("4000000000000"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			return v, nil
		}
	case "GTPtunnelEndpoint-ExtIEs":
		switch extensionId {
		case 396: // id-QoS-Mapping-Information -> QoSMappingInformation
			var v QoSMappingInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension QoSMappingInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "HandoverRestrictionList-ExtIEs":
		switch extensionId {
		case 202: // id-NRrestrictioninEPSasSecondaryRAT -> NRrestrictioninEPSasSecondaryRAT (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRrestrictioninEPSasSecondaryRAT (%d): %w", extensionId, err)
			}
			result := NRrestrictioninEPSasSecondaryRAT(v)
			return &result, nil
		case 301: // id-CNTypeRestrictions -> CNTypeRestrictions (SEQUENCE_OF)
			v, err := UnmarshalAPERCNTypeRestrictionsFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CNTypeRestrictions (%d): %w", extensionId, err)
			}
			return &v, nil
		case 305: // id-NRrestrictionin5GS -> NRrestrictionin5GS (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRrestrictionin5GS (%d): %w", extensionId, err)
			}
			result := NRrestrictionin5GS(v)
			return &result, nil
		case 332: // id-LastNG-RANPLMNIdentity -> PLMNIdentity (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PLMNIdentity (%d): %w", extensionId, err)
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
		case 437: // id-RAT-Restrictions -> RATRestrictions (SEQUENCE_OF)
			v, err := UnmarshalAPERRATRestrictionsFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension RATRestrictions (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "LastVisitedEUTRANCellInformation-ExtIEs":
		switch extensionId {
		case 77: // id-Time-UE-StayedInCell-EnhancedGranularity -> TimeUEStayedInCellEnhancedGranularity (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(40950), false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TimeUEStayedInCellEnhancedGranularity (%d): %w", extensionId, err)
			}
			result := TimeUEStayedInCellEnhancedGranularity(v)
			return &result, nil
		case 80: // id-HO-cause -> Cause
			var v Cause
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension Cause (%d): %w", extensionId, err)
			}
			return &v, nil
		case 418: // id-PSCell-UE-HistoryInformation -> PSCellUEHistoryInformation (SEQUENCE_OF)
			v, err := UnmarshalAPERPSCellUEHistoryInformationFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PSCellUEHistoryInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "LocationReportingInformation-ExtIEs":
		switch extensionId {
		case 409: // id-AdditionLocationInformation -> AdditionLocationInformation (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension AdditionLocationInformation (%d): %w", extensionId, err)
			}
			result := AdditionLocationInformation(v)
			return &result, nil
		}
	case "M4Configuration-ExtIEs":
		switch extensionId {
		case 442: // id-M4ReportAmount -> M4ReportAmountMDT (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension M4ReportAmountMDT (%d): %w", extensionId, err)
			}
			result := M4ReportAmountMDT(v)
			return &result, nil
		}
	case "M5Configuration-ExtIEs":
		switch extensionId {
		case 443: // id-M5ReportAmount -> M5ReportAmountMDT (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension M5ReportAmountMDT (%d): %w", extensionId, err)
			}
			result := M5ReportAmountMDT(v)
			return &result, nil
		}
	case "M6Configuration-ExtIEs":
		switch extensionId {
		case 444: // id-M6ReportAmount -> M6ReportAmountMDT (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension M6ReportAmountMDT (%d): %w", extensionId, err)
			}
			result := M6ReportAmountMDT(v)
			return &result, nil
		}
	case "M7Configuration-ExtIEs":
		switch extensionId {
		case 445: // id-M7ReportAmount -> M7ReportAmountMDT (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension M7ReportAmountMDT (%d): %w", extensionId, err)
			}
			result := M7ReportAmountMDT(v)
			return &result, nil
		}
	case "MDT-Configuration-ExtIEs":
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
		case 88: // id-MDT-Location-Info -> MDTLocationInfo (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 8, 8, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MDTLocationInfo (%d): %w", extensionId, err)
			}
			result := MDTLocationInfo{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 90: // id-SignallingBasedMDTPLMNList -> MDTPLMNList (SEQUENCE_OF)
			v, err := UnmarshalAPERMDTPLMNListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MDTPLMNList (%d): %w", extensionId, err)
			}
			return &v, nil
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
	case "Neighbour-Information-ExtIEs":
		switch extensionId {
		case 76: // id-NeighbourTAC -> TAC (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 2, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TAC (%d): %w", extensionId, err)
			}
			result := TAC(v)
			return &result, nil
		case 94: // id-eARFCNExtension -> EARFCNExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("65536"), runtime.MustParseBigIntDecimal("262143"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EARFCNExtension (%d): %w", extensionId, err)
			}
			return v, nil
		}
	case "NRFreqInfo-ExtIEs":
		switch extensionId {
		case 388: // id-FrequencyShift7p5khz -> FrequencyShift7p5khz (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension FrequencyShift7p5khz (%d): %w", extensionId, err)
			}
			result := FrequencyShift7p5khz(v)
			return &result, nil
		}
	case "NRRAReportList-Item-ExtIEs":
		switch extensionId {
		case 448: // id-PSCellListContainer -> PSCellListContainer (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension PSCellListContainer (%d): %w", extensionId, err)
			}
			result := PSCellListContainer(v)
			return &result, nil
		}
	case "NRNeighbour-Information-ExtIEs":
		switch extensionId {
		case 380: // id-CSI-RSTransmissionIndication -> CSIRSTransmissionIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CSIRSTransmissionIndication (%d): %w", extensionId, err)
			}
			result := CSIRSTransmissionIndication(v)
			return &result, nil
		case 389: // id-SSB-PositionsInBurst -> SSBPositionsInBurst
			var v SSBPositionsInBurst
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SSBPositionsInBurst (%d): %w", extensionId, err)
			}
			return &v, nil
		case 390: // id-NRCellPRACHConfig -> NRCellPRACHConfig (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCellPRACHConfig (%d): %w", extensionId, err)
			}
			result := NRCellPRACHConfig(v)
			return &result, nil
		case 433: // id-Additional-Measurement-Timing-Configuration-List -> AdditionalMeasurementTimingConfigurationList (SEQUENCE_OF)
			v, err := UnmarshalAPERAdditionalMeasurementTimingConfigurationListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension AdditionalMeasurementTimingConfigurationList (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "NRRadioResourceStatus-ExtIEs":
		switch extensionId {
		case 439: // id-MIMOPRBusageInformation -> MIMOPRBusageInformation
			var v MIMOPRBusageInformation
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension MIMOPRBusageInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ProSeAuthorized-ExtIEs":
		switch extensionId {
		case 149: // id-ProSeUEtoNetworkRelaying -> ProSeUEtoNetworkRelaying (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ProSeUEtoNetworkRelaying (%d): %w", extensionId, err)
			}
			result := ProSeUEtoNetworkRelaying(v)
			return &result, nil
		}
	case "RadioResourceStatus-ExtIEs":
		switch extensionId {
		case 193: // id-DL-scheduling-PDCCH-CCE-usage -> DLSchedulingPDCCHCCEUsage (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(100), false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension DLSchedulingPDCCHCCEUsage (%d): %w", extensionId, err)
			}
			result := DLSchedulingPDCCHCCEUsage(v)
			return &result, nil
		case 194: // id-UL-scheduling-PDCCH-CCE-usage -> ULSchedulingPDCCHCCEUsage (INTEGER)
			v, err := per.DecodeIntegerAligned(bb, int64Ptr(0), int64Ptr(100), false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ULSchedulingPDCCHCCEUsage (%d): %w", extensionId, err)
			}
			result := ULSchedulingPDCCHCCEUsage(v)
			return &result, nil
		}
	case "RelativeNarrowbandTxPower-ExtIEs":
		switch extensionId {
		case 148: // id-enhancedRNTP -> EnhancedRNTP
			var v EnhancedRNTP
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension EnhancedRNTP (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "RSRPMRList-ExtIEs":
		switch extensionId {
		case 147: // id-UEID -> UEID (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 16, 16, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension UEID (%d): %w", extensionId, err)
			}
			result := UEID{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "ServedCell-ExtIEs":
		switch extensionId {
		case 327: // id-NRNeighbourInfoToAdd -> NRNeighbourInformation (SEQUENCE_OF)
			v, err := UnmarshalAPERNRNeighbourInformationFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRNeighbourInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		case 434: // id-ServedCellSpecificInfoReq-NR -> ServedCellSpecificInfoReqNR (SEQUENCE_OF)
			v, err := UnmarshalAPERServedCellSpecificInfoReqNRFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ServedCellSpecificInfoReqNR (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ServedCell-Information-ExtIEs":
		switch extensionId {
		case 41: // id-Number-of-Antennaports -> NumberOfAntennaports (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NumberOfAntennaports (%d): %w", extensionId, err)
			}
			result := NumberOfAntennaports(v)
			return &result, nil
		case 55: // id-PRACH-Configuration -> PRACHConfiguration
			var v PRACHConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension PRACHConfiguration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 56: // id-MBSFN-Subframe-Info -> MBSFNSubframeInfolist (SEQUENCE_OF)
			v, err := UnmarshalAPERMBSFNSubframeInfolistFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MBSFNSubframeInfolist (%d): %w", extensionId, err)
			}
			return &v, nil
		case 70: // id-CSG-Id -> CSGId (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 27, 27, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CSGId (%d): %w", extensionId, err)
			}
			result := CSGId{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 79: // id-MBMS-Service-Area-List -> MBMSServiceAreaIdentityList (SEQUENCE_OF)
			v, err := UnmarshalAPERMBMSServiceAreaIdentityListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MBMSServiceAreaIdentityList (%d): %w", extensionId, err)
			}
			return &v, nil
		case 84: // id-MultibandInfoList -> MultibandInfoList (SEQUENCE_OF)
			v, err := UnmarshalAPERMultibandInfoListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MultibandInfoList (%d): %w", extensionId, err)
			}
			return &v, nil
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
		case 336: // id-BPLMN-ID-Info-EUTRA -> BPLMNIDInfoEUTRA (SEQUENCE_OF)
			v, err := UnmarshalAPERBPLMNIDInfoEUTRAFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension BPLMNIDInfoEUTRA (%d): %w", extensionId, err)
			}
			return &v, nil
		case 373: // id-NPRACHConfiguration -> NPRACHConfiguration
			var v NPRACHConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension NPRACHConfiguration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 406: // id-SFN-Offset -> SFNOffset
			var v SFNOffset
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SFNOffset (%d): %w", extensionId, err)
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
	case "SULInformation-ExtIEs":
		switch extensionId {
		case 386: // id-CarrierList -> NRCarrierList (SEQUENCE_OF)
			v, err := UnmarshalAPERNRCarrierListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCarrierList (%d): %w", extensionId, err)
			}
			return &v, nil
		case 388: // id-FrequencyShift7p5khz -> FrequencyShift7p5khz (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension FrequencyShift7p5khz (%d): %w", extensionId, err)
			}
			result := FrequencyShift7p5khz(v)
			return &result, nil
		}
	case "TDD-Info-ExtIEs":
		switch extensionId {
		case 97: // id-AdditionalSpecialSubframe-Info -> AdditionalSpecialSubframeInfo
			var v AdditionalSpecialSubframeInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension AdditionalSpecialSubframeInfo (%d): %w", extensionId, err)
			}
			return &v, nil
		case 94: // id-eARFCNExtension -> EARFCNExtension (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("65536"), runtime.MustParseBigIntDecimal("262143"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EARFCNExtension (%d): %w", extensionId, err)
			}
			return v, nil
		case 179: // id-AdditionalSpecialSubframeExtension-Info -> AdditionalSpecialSubframeExtensionInfo
			var v AdditionalSpecialSubframeExtensionInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension AdditionalSpecialSubframeExtensionInfo (%d): %w", extensionId, err)
			}
			return &v, nil
		case 177: // id-OffsetOfNbiotChannelNumberToDL-EARFCN -> OffsetOfNbiotChannelNumberToEARFCN (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 21, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension OffsetOfNbiotChannelNumberToEARFCN (%d): %w", extensionId, err)
			}
			result := OffsetOfNbiotChannelNumberToEARFCN(v)
			return &result, nil
		case 338: // id-NBIoT-UL-DL-AlignmentOffset -> NBIoTULDLAlignmentOffset (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 3, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NBIoTULDLAlignmentOffset (%d): %w", extensionId, err)
			}
			result := NBIoTULDLAlignmentOffset(v)
			return &result, nil
		}
	case "TDD-InfoNeighbourServedNRCell-Information-ExtIEs":
		switch extensionId {
		case 399: // id-IntendedTDD-DL-ULConfiguration-NR -> IntendedTDDDLULConfigurationNR (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension IntendedTDDDLULConfigurationNR (%d): %w", extensionId, err)
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
		case 386: // id-CarrierList -> NRCarrierList (SEQUENCE_OF)
			v, err := UnmarshalAPERNRCarrierListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCarrierList (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "TraceActivation-ExtIEs":
		switch extensionId {
		case 72: // id-MDTConfiguration -> MDTConfiguration
			var v MDTConfiguration
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension MDTConfiguration (%d): %w", extensionId, err)
			}
			return &v, nil
		case 195: // id-UEAppLayerMeasConfig -> UEAppLayerMeasConfig
			var v UEAppLayerMeasConfig
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension UEAppLayerMeasConfig (%d): %w", extensionId, err)
			}
			return &v, nil
		case 375: // id-MDTConfigurationNR -> MDTConfigurationNR (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MDTConfigurationNR (%d): %w", extensionId, err)
			}
			result := MDTConfigurationNR(v)
			return &result, nil
		case 405: // id-TraceCollectionEntityURI -> URIAddress (VisibleString)
			v, err := per.DecodeKnownMultiplierStringAligned(bb, 7, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension URIAddress (%d): %w", extensionId, err)
			}
			result := URIAddress(v)
			return &result, nil
		}
	case "UEAggregate-MaximumBitrate-ExtIEs":
		switch extensionId {
		case 200: // id-extended-uEaggregateMaximumBitRateDownlink -> ExtendedBitRate (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("10000000001"), runtime.MustParseBigIntDecimal("4000000000000"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ExtendedBitRate (%d): %w", extensionId, err)
			}
			return v, nil
		case 201: // id-extended-uEaggregateMaximumBitRateUplink -> ExtendedBitRate (INTEGER)
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
	case "UE-ContextInformation-ExtIEs":
		switch extensionId {
		case 74: // id-ManagementBasedMDTallowed -> ManagementBasedMDTallowed (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ManagementBasedMDTallowed (%d): %w", extensionId, err)
			}
			result := ManagementBasedMDTallowed(v)
			return &result, nil
		case 89: // id-ManagementBasedMDTPLMNList -> MDTPLMNList (SEQUENCE_OF)
			v, err := UnmarshalAPERMDTPLMNListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MDTPLMNList (%d): %w", extensionId, err)
			}
			return &v, nil
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
	case "E-RABs-ToBeSetup-ItemExtIEs":
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
		case 369: // id-Ethernet-Type -> EthernetType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EthernetType (%d): %w", extensionId, err)
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
	case "E-RABs-Admitted-Item-ExtIEs":
		switch extensionId {
		case 366: // id-DAPSResponseInfo -> DAPSResponseInfo
			var v DAPSResponseInfo
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension DAPSResponseInfo (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "E-RABs-SubjectToStatusTransfer-ItemExtIEs":
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
		case 150: // id-ReceiveStatusOfULPDCPSDUsPDCP-SNlength18 -> ReceiveStatusOfULPDCPSDUsPDCPSNlength18 (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAligned(bb, 1, 131072, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ReceiveStatusOfULPDCPSDUsPDCPSNlength18 (%d): %w", extensionId, err)
			}
			result := ReceiveStatusOfULPDCPSDUsPDCPSNlength18{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		case 151: // id-ULCOUNTValuePDCP-SNlength18 -> COUNTvaluePDCPSNlength18
			var v COUNTvaluePDCPSNlength18
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension COUNTvaluePDCPSNlength18 (%d): %w", extensionId, err)
			}
			return &v, nil
		case 152: // id-DLCOUNTValuePDCP-SNlength18 -> COUNTvaluePDCPSNlength18
			var v COUNTvaluePDCPSNlength18
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension COUNTvaluePDCPSNlength18 (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "CellInformation-Item-ExtIEs":
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
	case "ServedCellsToModify-Item-ExtIEs":
		switch extensionId {
		case 59: // id-DeactivationIndication -> DeactivationIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension DeactivationIndication (%d): %w", extensionId, err)
			}
			result := DeactivationIndication(v)
			return &result, nil
		case 328: // id-NRNeighbourInfoToModify -> NRNeighbourInformation (SEQUENCE_OF)
			v, err := UnmarshalAPERNRNeighbourInformationFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRNeighbourInformation (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "CellMeasurementResult-Item-ExtIEs":
		switch extensionId {
		case 42: // id-CompositeAvailableCapacityGroup -> CompositeAvailableCapacityGroup
			var v CompositeAvailableCapacityGroup
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension CompositeAvailableCapacityGroup (%d): %w", extensionId, err)
			}
			return &v, nil
		case 63: // id-ABS-Status -> ABSStatus
			var v ABSStatus
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension ABSStatus (%d): %w", extensionId, err)
			}
			return &v, nil
		case 110: // id-RSRPMRList -> RSRPMRList (SEQUENCE_OF)
			v, err := UnmarshalAPERRSRPMRListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension RSRPMRList (%d): %w", extensionId, err)
			}
			return &v, nil
		case 146: // id-CSIReportList -> CSIReportList (SEQUENCE_OF)
			v, err := UnmarshalAPERCSIReportListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CSIReportList (%d): %w", extensionId, err)
			}
			return &v, nil
		case 170: // id-CellReportingIndicator -> CellReportingIndicator (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CellReportingIndicator (%d): %w", extensionId, err)
			}
			result := CellReportingIndicator(v)
			return &result, nil
		case 417: // id-MeasurementResultforNRCellsPossiblyAggregated -> MeasurementResultforNRCellsPossiblyAggregated (SEQUENCE_OF)
			v, err := UnmarshalAPERMeasurementResultforNRCellsPossiblyAggregatedFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension MeasurementResultforNRCellsPossiblyAggregated (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "E-RABs-ToBeAdded-Item-SCG-BearerExtIEs":
		switch extensionId {
		case 166: // id-Correlation-ID -> CorrelationID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CorrelationID (%d): %w", extensionId, err)
			}
			result := CorrelationID(v)
			return &result, nil
		case 167: // id-SIPTO-Correlation-ID -> CorrelationID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CorrelationID (%d): %w", extensionId, err)
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
		case 369: // id-Ethernet-Type -> EthernetType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EthernetType (%d): %w", extensionId, err)
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
	case "E-RABs-ToBeAdded-Item-Split-BearerExtIEs":
		switch extensionId {
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "E-RABs-Admitted-ToBeAdded-Item-SCG-BearerExtIEs":
		switch extensionId {
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "E-RABs-Admitted-ToBeAdded-Item-Split-BearerExtIEs":
		switch extensionId {
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "E-RABs-ToBeAdded-ModReqItem-SCG-BearerExtIEs":
		switch extensionId {
		case 166: // id-Correlation-ID -> CorrelationID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CorrelationID (%d): %w", extensionId, err)
			}
			result := CorrelationID(v)
			return &result, nil
		case 167: // id-SIPTO-Correlation-ID -> CorrelationID (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 4, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CorrelationID (%d): %w", extensionId, err)
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
		case 369: // id-Ethernet-Type -> EthernetType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EthernetType (%d): %w", extensionId, err)
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
	case "E-RABs-ToBeAdded-ModReqItem-Split-BearerExtIEs":
		switch extensionId {
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "E-RABs-Admitted-ToBeAdded-ModAckItem-SCG-BearerExtIEs":
		switch extensionId {
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "E-RABs-Admitted-ToBeAdded-ModAckItem-Split-BearerExtIEs":
		switch extensionId {
		case 412: // id-SourceDLForwardingIPAddress -> TransportLayerAddress (BIT_STRING)
			bytes, bitLen, err := per.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TransportLayerAddress (%d): %w", extensionId, err)
			}
			result := TransportLayerAddress{Bytes: bytes, BitLength: int(bitLen)}
			return &result, nil
		}
	case "UE-ContextInformationRetrieve-ExtIEs":
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
	case "E-RABs-ToBeSetupRetrieve-ItemExtIEs":
		switch extensionId {
		case 185: // id-uL-GTPtunnelEndpoint -> GTPtunnelEndpoint
			var v GTPtunnelEndpoint
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension GTPtunnelEndpoint (%d): %w", extensionId, err)
			}
			return &v, nil
		case 306: // id-dL-Forwarding -> DLForwarding (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension DLForwarding (%d): %w", extensionId, err)
			}
			result := DLForwarding(v)
			return &result, nil
		case 369: // id-Ethernet-Type -> EthernetType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EthernetType (%d): %w", extensionId, err)
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
	case "E-RABs-ToBeAdded-SgNBAddReq-Item-SgNBPDCPpresentExtIEs":
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
		case 369: // id-Ethernet-Type -> EthernetType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EthernetType (%d): %w", extensionId, err)
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
	case "E-RABs-ToBeAdded-SgNBAddReq-Item-SgNBPDCPnotpresentExtIEs":
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
	case "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item-SgNBPDCPpresentExtIEs":
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
	case "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item-SgNBPDCPnotpresentExtIEs":
		switch extensionId {
		case 314: // id-lCID -> LCID (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("32"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension LCID (%d): %w", extensionId, err)
			}
			return v, nil
		}
	case "UE-ContextInformationSgNBModReqExtIEs":
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
	case "E-RABs-ToBeAdded-SgNBModReq-Item-SgNBPDCPpresentExtIEs":
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
		case 369: // id-Ethernet-Type -> EthernetType (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 1, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension EthernetType (%d): %w", extensionId, err)
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
	case "E-RABs-ToBeAdded-SgNBModReq-Item-SgNBPDCPnotpresentExtIEs":
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
	case "E-RABs-ToBeModified-SgNBModReq-Item-SgNBPDCPpresentExtIEs":
		switch extensionId {
		case 300: // id-RLC-Status -> RLCStatus
			var v RLCStatus
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension RLCStatus (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "E-RABs-ToBeModified-SgNBModReq-Item-SgNBPDCPnotpresentExtIEs":
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
	case "E-RABs-Admitted-ToBeAdded-SgNBModAck-Item-SgNBPDCPpresentExtIEs":
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
	case "E-RABs-Admitted-ToBeAdded-SgNBModAck-Item-SgNBPDCPnotpresentExtIEs":
		switch extensionId {
		case 314: // id-lCID -> LCID (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("32"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension LCID (%d): %w", extensionId, err)
			}
			return v, nil
		}
	case "E-RABs-Admitted-ToBeModified-SgNBModAck-Item-SgNBPDCPpresentExtIEs":
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
	case "E-RABs-Admitted-ToBeModified-SgNBModAck-Item-SgNBPDCPnotpresentExtIEs":
		switch extensionId {
		case 312: // id-secondarysgNBDLGTPTEIDatPDCP -> GTPtunnelEndpoint
			var v GTPtunnelEndpoint
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension GTPtunnelEndpoint (%d): %w", extensionId, err)
			}
			return &v, nil
		case 300: // id-RLC-Status -> RLCStatus
			var v RLCStatus
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension RLCStatus (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "E-RABs-ToBeReleased-SgNBModReqd-ItemExtIEs":
		switch extensionId {
		case 317: // id-RLCMode-transferred -> RLCMode (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 4, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension RLCMode (%d): %w", extensionId, err)
			}
			result := RLCMode(v)
			return &result, nil
		}
	case "E-RABs-ToBeModified-SgNBModReqd-Item-SgNBPDCPpresentExtIEs":
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
	case "E-RABs-ToBeModified-SgNBModReqd-Item-SgNBPDCPnotpresentExtIEs":
		switch extensionId {
		case 300: // id-RLC-Status -> RLCStatus
			var v RLCStatus
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension RLCStatus (%d): %w", extensionId, err)
			}
			return &v, nil
		case 314: // id-lCID -> LCID (INTEGER)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("32"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension LCID (%d): %w", extensionId, err)
			}
			return v, nil
		}
	case "E-RABs-AdmittedToBeModified-SgNBModConf-Item-SgNBPDCPnotpresentExtIEs":
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
	case "E-RABs-ToBeReleased-SgNBChaConf-Item-SgNBPDCPpresentExtIEs":
		switch extensionId {
		case 441: // id-AdditionalListofForwardingGTPTunnelEndpoint -> AdditionalListofForwardingGTPTunnelEndpoint (SEQUENCE_OF)
			v, err := UnmarshalAPERAdditionalListofForwardingGTPTunnelEndpointFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension AdditionalListofForwardingGTPTunnelEndpoint (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "En-gNBServedCells-ExtIEs":
		switch extensionId {
		case 434: // id-ServedCellSpecificInfoReq-NR -> ServedCellSpecificInfoReqNR (SEQUENCE_OF)
			v, err := UnmarshalAPERServedCellSpecificInfoReqNRFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ServedCellSpecificInfoReqNR (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "ServedNRCell-Information-ExtIEs":
		switch extensionId {
		case 334: // id-additionalPLMNs-Item -> AdditionalPLMNsItem (SEQUENCE_OF)
			v, err := UnmarshalAPERAdditionalPLMNsItemFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension AdditionalPLMNsItem (%d): %w", extensionId, err)
			}
			return &v, nil
		case 337: // id-BPLMN-ID-Info-NR -> BPLMNIDInfoNR (SEQUENCE_OF)
			v, err := UnmarshalAPERBPLMNIDInfoNRFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension BPLMNIDInfoNR (%d): %w", extensionId, err)
			}
			return &v, nil
		case 389: // id-SSB-PositionsInBurst -> SSBPositionsInBurst
			var v SSBPositionsInBurst
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SSBPositionsInBurst (%d): %w", extensionId, err)
			}
			return &v, nil
		case 390: // id-NRCellPRACHConfig -> NRCellPRACHConfig (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCellPRACHConfig (%d): %w", extensionId, err)
			}
			result := NRCellPRACHConfig(v)
			return &result, nil
		case 380: // id-CSI-RSTransmissionIndication -> CSIRSTransmissionIndication (ENUMERATED)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding extension CSIRSTransmissionIndication (%d): %w", extensionId, err)
			}
			result := CSIRSTransmissionIndication(v)
			return &result, nil
		case 406: // id-SFN-Offset -> SFNOffset
			var v SFNOffset
			if err := v.UnmarshalAPERFrom(bb); err != nil {
				return nil, fmt.Errorf("decoding extension SFNOffset (%d): %w", extensionId, err)
			}
			return &v, nil
		case 433: // id-Additional-Measurement-Timing-Configuration-List -> AdditionalMeasurementTimingConfigurationList (SEQUENCE_OF)
			v, err := UnmarshalAPERAdditionalMeasurementTimingConfigurationListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension AdditionalMeasurementTimingConfigurationList (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "FDD-InfoServedNRCell-Information-ExtIEs":
		switch extensionId {
		case 387: // id-ULCarrierList -> NRCarrierList (SEQUENCE_OF)
			v, err := UnmarshalAPERNRCarrierListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCarrierList (%d): %w", extensionId, err)
			}
			return &v, nil
		case 381: // id-DLCarrierList -> NRCarrierList (SEQUENCE_OF)
			v, err := UnmarshalAPERNRCarrierListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCarrierList (%d): %w", extensionId, err)
			}
			return &v, nil
		}
	case "TDD-InfoServedNRCell-Information-ExtIEs":
		switch extensionId {
		case 385: // id-TDDULDLConfigurationCommonNR -> TDDULDLConfigurationCommonNR (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension TDDULDLConfigurationCommonNR (%d): %w", extensionId, err)
			}
			result := TDDULDLConfigurationCommonNR(v)
			return &result, nil
		case 386: // id-CarrierList -> NRCarrierList (SEQUENCE_OF)
			v, err := UnmarshalAPERNRCarrierListFrom(bb)
			if err != nil {
				return nil, fmt.Errorf("decoding extension NRCarrierList (%d): %w", extensionId, err)
			}
			return &v, nil
		case 399: // id-IntendedTDD-DL-ULConfiguration-NR -> IntendedTDDDLULConfigurationNR (OCTET_STRING)
			v, err := per.DecodeOctetStringAligned(bb, 0, 0, false)
			if err != nil {
				return nil, fmt.Errorf("decoding extension IntendedTDDDLULConfigurationNR (%d): %w", extensionId, err)
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
	"GlobalRANNODEID.ChoiceExtension":                                 "Global-RAN-NODE-ID-ExtIEs",
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
	"ProcedureStageChoice.ChoiceExtension":                            "ProcedureStageChoice-ExtIEs",
	"RLFIndication.ProtocolIEs":                                       "RLFIndication-IEs",
	"RRCTransfer.ProtocolIEs":                                         "RRCTransfer-IEs",
	"RachIndication.ProtocolIEs":                                      "RachIndication-IEs",
	"ResetRequest.ProtocolIEs":                                        "ResetRequest-IEs",
	"ResetResponse.ProtocolIEs":                                       "ResetResponse-IEs",
	"ResourceStatusFailure.ProtocolIEs":                               "ResourceStatusFailure-IEs",
	"ResourceStatusRequest.ProtocolIEs":                               "ResourceStatusRequest-IEs",
	"ResourceStatusResponse.ProtocolIEs":                              "ResourceStatusResponse-IEs",
	"ResourceStatusUpdate.ProtocolIEs":                                "ResourceStatusUpdate-IEs",
	"RespondingNodeTypeEndcConfigUpdate.RespondENB":                   "ENB-ENDCConfigUpdateAckIEs",
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
	"SSBPositionsInBurst.ChoiceExtension":                             "SSB-PositionsInBurst-ExtIEs",
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
	"SensorNameConfig.ChoiceExtension":                                "SensorNameConfig-ExtIEs",
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
	"ABSInformationFDD.IEExtensions":                                          "ABSInformationFDD-ExtIEs",
	"ABSInformationTDD.IEExtensions":                                          "ABSInformationTDD-ExtIEs",
	"ABSStatus.IEExtensions":                                                  "ABS-Status-ExtIEs",
	"ASSecurityInformation.IEExtensions":                                      "AS-SecurityInformation-ExtIEs",
	"ActivatedCellListItem.IEExtensions":                                      "ActivatedCellList-Item-ExtIEs",
	"ActivatedNRCellListItem.IEExtensions":                                    "ActivatedNRCellList-Item-ExtIEs",
	"AdditionalListofForwardingGTPTunnelEndpointItem.IEExtensions":            "AdditionalListofForwardingGTPTunnelEndpoint-Item-ExtIEs",
	"AdditionalMeasurementTimingConfigurationItem.IEExtensions":               "Additional-Measurement-Timing-Configuration-Item-ExtIEs",
	"AdditionalSpecialSubframeExtensionInfo.IEExtensions":                     "AdditionalSpecialSubframeExtension-Info-ExtIEs",
	"AdditionalSpecialSubframeInfo.IEExtensions":                              "AdditionalSpecialSubframe-Info-ExtIEs",
	"AllocationAndRetentionPriority.IEExtensions":                             "AllocationAndRetentionPriority-ExtIEs",
	"BPLMNIDInfoEUTRAItem.IEExtension":                                        "BPLMN-ID-Info-EUTRA-Item-ExtIEs",
	"BPLMNIDInfoNRItem.IEExtension":                                           "BPLMN-ID-Info-NR-Item-ExtIEs",
	"BandInfo.IEExtensions":                                                   "BandInfo-ExtIEs",
	"BluetoothMeasurementConfiguration.IEExtensions":                          "BluetoothMeasurementConfiguration-ExtIEs",
	"CHOTimeBasedInformation.IEExtensions":                                    "CHOTimeBasedInformation-ExtIEs",
	"CHOinformationACK.IEExtensions":                                          "CHOinformation-ACK-ExtIEs",
	"CHOinformationAddReq.IEExtensions":                                       "CHOinformation-AddReq-ExtIEs",
	"CHOinformationModReq.IEExtensions":                                       "CHOinformation-ModReq-ExtIEs",
	"CHOinformationREQ.IEExtensions":                                          "CHOinformation-REQ-ExtIEs",
	"CNTypeRestrictionsItem.IEExtensions":                                     "CNTypeRestrictionsItem-ExtIEs",
	"COUNTValueExtended.IEExtensions":                                         "COUNTValueExtended-ExtIEs",
	"COUNTvalue.IEExtensions":                                                 "COUNTvalue-ExtIEs",
	"COUNTvaluePDCPSNlength18.IEExtensions":                                   "COUNTvaluePDCP-SNlength18-ExtIEs",
	"CPACcandidatePSCellsItem.IEExtensions":                                   "CPACcandidatePSCells-item-ExtIEs",
	"CPACinformationREQD.IEExtensions":                                        "CPACinformation-REQD-ExtIEs",
	"CPAinformationMOD.IEExtensions":                                          "CPAinformation-MOD-ExtIEs",
	"CPAinformationMODACK.IEExtensions":                                       "CPAinformation-MOD-ACK-ExtIEs",
	"CPAinformationREQ.IEExtensions":                                          "CPAinformation-REQ-ExtIEs",
	"CPAinformationREQACK.IEExtensions":                                       "CPAinformation-REQ-ACK-ExtIEs",
	"CPCTargetSgNBConfItem.IEExtensions":                                      "CPC-target-SgNB-conf-item-ExtIEs",
	"CPCTargetSgNBModItem.IEExtensions":                                       "CPC-target-SgNB-mod-item-ExtIEs",
	"CPCTargetSgNBReqdItem.IEExtensions":                                      "CPC-target-SgNB-reqd-item-ExtIEs",
	"CPCinformationCONF.IEExtensions":                                         "CPCinformation-CONF-ExtIEs",
	"CPCinformationNOTIFY.IEExtensions":                                       "CPCinformation-NOTIFY-ExtIEs",
	"CPCinformationREQD.IEExtensions":                                         "CPCinformation-REQD-ExtIEs",
	"CPCupdateMOD.IEExtensions":                                               "CPCupdate-MOD-ExtIEs",
	"CSIRSMTCConfigurationItem.IEExtensions":                                  "CSI-RS-MTC-Configuration-Item-ExtIEs",
	"CSIRSMTCNeighbourItem.IEExtensions":                                      "CSI-RS-MTC-Neighbour-Item-ExtIEs",
	"CSIRSNeighbourItem.IEExtensions":                                         "CSI-RS-Neighbour-Item-ExtIEs",
	"CSIReportListElem.IEExtensions":                                          "CSIReportList-ExtIEs",
	"CSIReportPerCSIProcessElem.IEExtensions":                                 "CSIReportPerCSIProcess-ExtIEs",
	"CSIReportPerCSIProcessItemElem.IEExtensions":                             "CSIReportPerCSIProcessItem-ExtIEs",
	"CellBasedMDT.IEExtensions":                                               "CellBasedMDT-ExtIEs",
	"CellBasedQMC.IEExtensions":                                               "CellBasedQMC-ExtIEs",
	"CellInformationItem.IEExtensions":                                        "CellInformation-Item-ExtIEs",
	"CellMeasurementResultEUTRAENDCItem.IEExtensions":                         "CellMeasurementResult-E-UTRA-ENDC-Item-ExtIEs",
	"CellMeasurementResultItem.IEExtensions":                                  "CellMeasurementResult-Item-ExtIEs",
	"CellMeasurementResultNRENDCItem.IEExtensions":                            "CellMeasurementResult-NR-ENDC-Item-ExtIEs",
	"CellReplacingInfo.IEExtensions":                                          "CellReplacingInfo-ExtIEs",
	"CellToReportEUTRAENDCItem.IEExtensions":                                  "CellToReport-E-UTRA-ENDC-Item-ExtIEs",
	"CellToReportItem.IEExtensions":                                           "CellToReport-Item-ExtIEs",
	"CellToReportNRENDCItem.IEExtensions":                                     "CellToReport-NR-ENDC-Item-ExtIEs",
	"CellType.IEExtensions":                                                   "CellType-ExtIEs",
	"CellandCapacityAssistInfo.IEExtensions":                                  "CellandCapacityAssistInfo-ExtIEs",
	"CoMPHypothesisSetItem.IEExtensions":                                      "CoMPHypothesisSetItem-ExtIEs",
	"CoMPInformation.IEExtensions":                                            "CoMPInformation-ExtIEs",
	"CoMPInformationItemElem.IEExtensions":                                    "CoMPInformationItem-ExtIEs",
	"CoMPInformationStartTimeElem.IEExtensions":                               "CoMPInformationStartTime-ExtIEs",
	"CompleteFailureCauseInformationItem.IEExtensions":                        "CompleteFailureCauseInformation-Item-ExtIEs",
	"CompositeAvailableCapacity.IEExtensions":                                 "CompositeAvailableCapacity-ExtIEs",
	"CompositeAvailableCapacityGroup.IEExtensions":                            "CompositeAvailableCapacityGroup-ExtIEs",
	"CriticalityDiagnostics.IEExtensions":                                     "CriticalityDiagnostics-ExtIEs",
	"CriticalityDiagnosticsIEListElem.IEExtensions":                           "CriticalityDiagnostics-IE-List-ExtIEs",
	"DAPSRequestInfo.IEExtensions":                                            "DAPSRequestInfo-ExtIEs",
	"DAPSResponseInfo.IEExtensions":                                           "DAPSResponseInfo-ExtIEs",
	"DLDiscarding.IEExtension":                                                "DLDiscarding-ExtIEs",
	"DataTrafficResourceIndication.IEExtensions":                              "DataTrafficResourceIndication-ExtIEs",
	"DeliveryStatus.IEExtensions":                                             "DeliveryStatus-ExtIEs",
	"DynamicNAICSInformation.IEExtensions":                                    "DynamicNAICSInformation-ExtIEs",
	"ECGI.IEExtensions":                                                       "ECGI-ExtIEs",
	"ENDCResourceConfiguration.IEExtensions":                                  "EN-DC-ResourceConfigurationExtIEs",
	"ERABActivityNotifyItem.IEExtensions":                                     "ERABActivityNotifyItem-ExtIEs",
	"ERABItem.IEExtensions":                                                   "E-RAB-Item-ExtIEs",
	"ERABLevelQoSParameters.IEExtensions":                                     "E-RAB-Level-QoS-Parameters-ExtIEs",
	"ERABUsageReportItem.IEExtensions":                                        "E-RABUsageReport-Item-ExtIEs",
	"ERABsAdmittedItem.IEExtensions":                                          "E-RABs-Admitted-Item-ExtIEs",
	"ERABsAdmittedToBeAddedItemSCGBearer.IEExtensions":                        "E-RABs-Admitted-ToBeAdded-Item-SCG-BearerExtIEs",
	"ERABsAdmittedToBeAddedItemSplitBearer.IEExtensions":                      "E-RABs-Admitted-ToBeAdded-Item-Split-BearerExtIEs",
	"ERABsAdmittedToBeAddedModAckItemSCGBearer.IEExtensions":                  "E-RABs-Admitted-ToBeAdded-ModAckItem-SCG-BearerExtIEs",
	"ERABsAdmittedToBeAddedModAckItemSplitBearer.IEExtensions":                "E-RABs-Admitted-ToBeAdded-ModAckItem-Split-BearerExtIEs",
	"ERABsAdmittedToBeAddedSgNBAddReqAckItem.IEExtensions":                    "E-RABs-ToBeAdded-SgNBAddReqAck-ItemExtIEs",
	"ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPnotpresent.IEExtensions":  "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsAdmittedToBeAddedSgNBAddReqAckItemSgNBPDCPpresent.IEExtensions":     "E-RABs-Admitted-ToBeAdded-SgNBAddReqAck-Item-SgNBPDCPpresentExtIEs",
	"ERABsAdmittedToBeAddedSgNBModAckItem.IEExtensions":                       "E-RABs-Admitted-ToBeAdded-SgNBModAck-ItemExtIEs",
	"ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPnotpresent.IEExtensions":     "E-RABs-Admitted-ToBeAdded-SgNBModAck-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsAdmittedToBeAddedSgNBModAckItemSgNBPDCPpresent.IEExtensions":        "E-RABs-Admitted-ToBeAdded-SgNBModAck-Item-SgNBPDCPpresentExtIEs",
	"ERABsAdmittedToBeModifiedModAckItemSCGBearer.IEExtensions":               "E-RABs-Admitted-ToBeModified-ModAckItem-SCG-BearerExtIEs",
	"ERABsAdmittedToBeModifiedModAckItemSplitBearer.IEExtensions":             "E-RABs-Admitted-ToBeModified-ModAckItem-Split-BearerExtIEs",
	"ERABsAdmittedToBeModifiedSgNBModAckItem.IEExtensions":                    "E-RABs-ToBeAdded-SgNBModAck-ItemExtIEs",
	"ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPnotpresent.IEExtensions":  "E-RABs-Admitted-ToBeModified-SgNBModAck-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsAdmittedToBeModifiedSgNBModAckItemSgNBPDCPpresent.IEExtensions":     "E-RABs-Admitted-ToBeModified-SgNBModAck-Item-SgNBPDCPpresentExtIEs",
	"ERABsAdmittedToBeModifiedSgNBModConfItem.IEExtensions":                   "E-RABs-AdmittedToBeModified-SgNBModConf-ItemExtIEs",
	"ERABsAdmittedToBeModifiedSgNBModConfItemSgNBPDCPnotpresent.IEExtensions": "E-RABs-AdmittedToBeModified-SgNBModConf-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsAdmittedToBeModifiedSgNBModConfItemSgNBPDCPpresent.IEExtensions":    "E-RABs-AdmittedToBeModified-SgNBModConf-Item-SgNBPDCPpresentExtIEs",
	"ERABsAdmittedToBeReleasedModAckItemSCGBearer.IEExtensions":               "E-RABs-Admitted-ToBeReleased-ModAckItem-SCG-BearerExtIEs",
	"ERABsAdmittedToBeReleasedModAckItemSplitBearer.IEExtensions":             "E-RABs-Admitted-ToBeReleased-ModAckItem-Split-BearerExtIEs",
	"ERABsAdmittedToBeReleasedSgNBModAckItemSgNBPDCPnotpresent.IEExtensions":  "E-RABs-Admitted-ToBeReleased-SgNBModAck-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsAdmittedToBeReleasedSgNBModAckItemSgNBPDCPpresent.IEExtensions":     "E-RABs-Admitted-ToBeReleased-SgNBModAck-Item-SgNBPDCPpresentExtIEs",
	"ERABsAdmittedToBeReleasedSgNBRelReqAckItem.IEExtensions":                 "E-RABs-Admitted-ToBeReleased-SgNBRelReqAck-ItemExtIEs",
	"ERABsAdmittedToReleasedSgNBModAckItem.IEExtensions":                      "E-RABs-ToBeReleased-SgNBModAck-ItemExtIEs",
	"ERABsDataForwardingAddressItem.IEExtensions":                             "E-RABs-DataForwardingAddress-ItemExtIEs",
	"ERABsSubjectToCounterCheckItem.IEExtensions":                             "E-RABs-SubjectToCounterCheckItemExtIEs",
	"ERABsSubjectToDLDiscardingItem.IEExtension":                              "E-RABsSubjectToDLDiscarding-Item-ExtIEs",
	"ERABsSubjectToEarlyStatusTransferItem.IEExtension":                       "E-RABsSubjectToEarlyStatusTransfer-Item-ExtIEs",
	"ERABsSubjectToSgNBCounterCheckItem.IEExtensions":                         "E-RABs-SubjectToSgNBCounterCheck-ItemExtIEs",
	"ERABsSubjectToStatusTransferItem.IEExtensions":                           "E-RABs-SubjectToStatusTransfer-ItemExtIEs",
	"ERABsToBeAddedItemSCGBearer.IEExtensions":                                "E-RABs-ToBeAdded-Item-SCG-BearerExtIEs",
	"ERABsToBeAddedItemSplitBearer.IEExtensions":                              "E-RABs-ToBeAdded-Item-Split-BearerExtIEs",
	"ERABsToBeAddedModReqItemSCGBearer.IEExtensions":                          "E-RABs-ToBeAdded-ModReqItem-SCG-BearerExtIEs",
	"ERABsToBeAddedModReqItemSplitBearer.IEExtensions":                        "E-RABs-ToBeAdded-ModReqItem-Split-BearerExtIEs",
	"ERABsToBeAddedSgNBAddReqItem.IEExtensions":                               "E-RABs-ToBeAdded-SgNBAddReq-ItemExtIEs",
	"ERABsToBeAddedSgNBAddReqItemSgNBPDCPnotpresent.IEExtensions":             "E-RABs-ToBeAdded-SgNBAddReq-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsToBeAddedSgNBAddReqItemSgNBPDCPpresent.IEExtensions":                "E-RABs-ToBeAdded-SgNBAddReq-Item-SgNBPDCPpresentExtIEs",
	"ERABsToBeAddedSgNBModReqItem.IEExtensions":                               "E-RABs-ToBeAdded-SgNBModReq-ItemExtIEs",
	"ERABsToBeAddedSgNBModReqItemSgNBPDCPnotpresent.IEExtensions":             "E-RABs-ToBeAdded-SgNBModReq-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsToBeAddedSgNBModReqItemSgNBPDCPpresent.IEExtensions":                "E-RABs-ToBeAdded-SgNBModReq-Item-SgNBPDCPpresentExtIEs",
	"ERABsToBeModifiedModReqItemSCGBearer.IEExtensions":                       "E-RABs-ToBeModified-ModReqItem-SCG-BearerExtIEs",
	"ERABsToBeModifiedModReqItemSplitBearer.IEExtensions":                     "E-RABs-ToBeModified-ModReqItem-Split-BearerExtIEs",
	"ERABsToBeModifiedSgNBModReqItem.IEExtensions":                            "E-RABs-ToBeModified-SgNBModReq-ItemExtIEs",
	"ERABsToBeModifiedSgNBModReqItemSgNBPDCPnotpresent.IEExtensions":          "E-RABs-ToBeModified-SgNBModReq-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsToBeModifiedSgNBModReqItemSgNBPDCPpresent.IEExtensions":             "E-RABs-ToBeModified-SgNBModReq-Item-SgNBPDCPpresentExtIEs",
	"ERABsToBeModifiedSgNBModReqdItem.IEExtensions":                           "E-RABs-ToBeModified-SgNBModReqd-ItemExtIEs",
	"ERABsToBeModifiedSgNBModReqdItemSgNBPDCPnotpresent.IEExtensions":         "E-RABs-ToBeModified-SgNBModReqd-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsToBeModifiedSgNBModReqdItemSgNBPDCPpresent.IEExtensions":            "E-RABs-ToBeModified-SgNBModReqd-Item-SgNBPDCPpresentExtIEs",
	"ERABsToBeReleasedModReqItemSCGBearer.IEExtensions":                       "E-RABs-ToBeReleased-ModReqItem-SCG-BearerExtIEs",
	"ERABsToBeReleasedModReqItemSplitBearer.IEExtensions":                     "E-RABs-ToBeReleased-ModReqItem-Split-BearerExtIEs",
	"ERABsToBeReleasedModReqdItem.IEExtensions":                               "E-RABs-ToBeReleased-ModReqdItemExtIEs",
	"ERABsToBeReleasedRelConfItemSCGBearer.IEExtensions":                      "E-RABs-ToBeReleased-RelConfItem-SCG-BearerExtIEs",
	"ERABsToBeReleasedRelConfItemSplitBearer.IEExtensions":                    "E-RABs-ToBeReleased-RelConfItem-Split-BearerExtIEs",
	"ERABsToBeReleasedRelReqItemSCGBearer.IEExtensions":                       "E-RABs-ToBeReleased-RelReqItem-SCG-BearerExtIEs",
	"ERABsToBeReleasedRelReqItemSplitBearer.IEExtensions":                     "E-RABs-ToBeReleased-RelReqItem-Split-BearerExtIEs",
	"ERABsToBeReleasedSgNBChaConfItem.IEExtensions":                           "E-RABs-ToBeReleased-SgNBChaConf-ItemExtIEs",
	"ERABsToBeReleasedSgNBChaConfItemSgNBPDCPnotpresent.IEExtensions":         "E-RABs-ToBeReleased-SgNBChaConf-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsToBeReleasedSgNBChaConfItemSgNBPDCPpresent.IEExtensions":            "E-RABs-ToBeReleased-SgNBChaConf-Item-SgNBPDCPpresentExtIEs",
	"ERABsToBeReleasedSgNBModReqItem.IEExtensions":                            "E-RABs-ToBeReleased-SgNBModReq-ItemExtIEs",
	"ERABsToBeReleasedSgNBModReqItemSgNBPDCPnotpresent.IEExtensions":          "E-RABs-ToBeReleased-SgNBModReq-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsToBeReleasedSgNBModReqItemSgNBPDCPpresent.IEExtensions":             "E-RABs-ToBeReleased-SgNBModReq-Item-SgNBPDCPpresentExtIEs",
	"ERABsToBeReleasedSgNBModReqdItem.IEExtensions":                           "E-RABs-ToBeReleased-SgNBModReqd-ItemExtIEs",
	"ERABsToBeReleasedSgNBRelConfItem.IEExtensions":                           "E-RABs-ToBeReleased-SgNBRelConf-ItemExtIEs",
	"ERABsToBeReleasedSgNBRelConfItemSgNBPDCPnotpresent.IEExtensions":         "E-RABs-ToBeReleased-SgNBRelConf-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsToBeReleasedSgNBRelConfItemSgNBPDCPpresent.IEExtensions":            "E-RABs-ToBeReleased-SgNBRelConf-Item-SgNBPDCPpresentExtIEs",
	"ERABsToBeReleasedSgNBRelReqItem.IEExtensions":                            "E-RABs-ToBeReleased-SgNBRelReq-ItemExtIEs",
	"ERABsToBeReleasedSgNBRelReqItemSgNBPDCPnotpresent.IEExtensions":          "E-RABs-ToBeReleased-SgNBRelReq-Item-SgNBPDCPnotpresentExtIEs",
	"ERABsToBeReleasedSgNBRelReqItemSgNBPDCPpresent.IEExtensions":             "E-RABs-ToBeReleased-SgNBRelReq-Item-SgNBPDCPpresentExtIEs",
	"ERABsToBeReleasedSgNBRelReqdItem.IEExtensions":                           "E-RABs-ToBeReleased-SgNBRelReqd-ItemExtIEs",
	"ERABsToBeSetupItem.IEExtensions":                                         "E-RABs-ToBeSetup-ItemExtIEs",
	"ERABsToBeSetupRetrieveItem.IEExtensions":                                 "E-RABs-ToBeSetupRetrieve-ItemExtIEs",
	"EnhancedRNTP.IEExtensions":                                               "EnhancedRNTP-ExtIEs",
	"EnhancedRNTPStartTime.IEExtensions":                                      "EnhancedRNTPStartTime-ExtIEs",
	"ExpectedUEActivityBehaviour.IEExtensions":                                "ExpectedUEActivityBehaviour-ExtIEs",
	"ExpectedUEBehaviour.IEExtensions":                                        "ExpectedUEBehaviour-ExtIEs",
	"ExtendedULInterferenceOverloadInfo.IEExtensions":                         "ExtendedULInterferenceOverloadInfo-ExtIEs",
	"FDDInfo.IEExtensions":                                                    "FDD-Info-ExtIEs",
	"FDDInfoNeighbourServedNRCellInformation.IEExtensions":                    "FDD-InfoNeighbourServedNRCell-Information-ExtIEs",
	"FDDInfoServedNRCellInformation.IEExtensions":                             "FDD-InfoServedNRCell-Information-ExtIEs",
	"FastMCGRecovery.IEExtensions":                                            "FastMCGRecovery-ExtIEs",
	"FirstDLCount.IEExtension":                                                "FirstDLCount-ExtIEs",
	"ForbiddenLAsItem.IEExtensions":                                           "ForbiddenLAs-Item-ExtIEs",
	"ForbiddenTAsItem.IEExtensions":                                           "ForbiddenTAs-Item-ExtIEs",
	"FreqBandNrItem.IEExtensions":                                             "FreqBandNrItem-ExtIEs",
	"GBRQosInformation.IEExtensions":                                          "GBR-QosInformation-ExtIEs",
	"GTPTLAItem.IEExtensions":                                                 "GTPTLA-Item-ExtIEs",
	"GTPtunnelEndpoint.IEExtensions":                                          "GTPtunnelEndpoint-ExtIEs",
	"GUGroupID.IEExtensions":                                                  "GU-Group-ID-ExtIEs",
	"GUMMEI.IEExtensions":                                                     "GUMMEI-ExtIEs",
	"GlobalENBID.IEExtensions":                                                "GlobalENB-ID-ExtIEs",
	"GlobalGNBID.IEExtensions":                                                "GlobalGNB-ID-ExtIEs",
	"HWLoadIndicator.IEExtensions":                                            "HWLoadIndicator-ExtIEs",
	"HandoverRestrictionList.IEExtensions":                                    "HandoverRestrictionList-ExtIEs",
	"LastVisitedEUTRANCellInformation.IEExtensions":                           "LastVisitedEUTRANCellInformation-ExtIEs",
	"LimitedListElem.IEExtensions":                                            "Limited-list-ExtIEs",
	"LocationInformationSgNB.IEExtensions":                                    "LocationInformationSgNB-ExtIEs",
	"LocationReportingInformation.IEExtensions":                               "LocationReportingInformation-ExtIEs",
	"M1PeriodicReporting.IEExtensions":                                        "M1PeriodicReporting-ExtIEs",
	"M1ThresholdEventA2.IEExtensions":                                         "M1ThresholdEventA2-ExtIEs",
	"M3Configuration.IEExtensions":                                            "M3Configuration-ExtIEs",
	"M4Configuration.IEExtensions":                                            "M4Configuration-ExtIEs",
	"M5Configuration.IEExtensions":                                            "M5Configuration-ExtIEs",
	"M6Configuration.IEExtensions":                                            "M6Configuration-ExtIEs",
	"M7Configuration.IEExtensions":                                            "M7Configuration-ExtIEs",
	"MBSFNSubframeInfo.IEExtensions":                                          "MBSFN-Subframe-Info-ExtIEs",
	"MDTConfiguration.IEExtensions":                                           "MDT-Configuration-ExtIEs",
	"MIMOPRBusageInformation.IEExtensions":                                    "MIMOPRBusageInformation-ExtIEs",
	"MeNBResourceCoordinationInformation.IEExtensions":                        "MeNBResourceCoordinationInformationExtIEs",
	"MeasurementFailureCauseItem.IEExtensions":                                "MeasurementFailureCause-Item-ExtIEs",
	"MeasurementInitiationResultItem.IEExtensions":                            "MeasurementInitiationResult-Item-ExtIEs",
	"MeasurementResultforNRCellsPossiblyAggregatedItem.IEExtension":           "MeasurementResultforNRCellsPossiblyAggregated-Item-ExtIEs",
	"MessageOversizeNotification.IEExtensions":                                "MessageOversizeNotification-ExtIEs",
	"NPRACHConfiguration.IEExtensions":                                        "NPRACHConfiguration-ExtIEs",
	"NPRACHConfigurationFDD.IEExtensions":                                     "NPRACHConfiguration-FDD-ExtIEs",
	"NPRACHConfigurationTDD.IEExtensions":                                     "NPRACHConfiguration-TDD-ExtIEs",
	"NRCGI.IEExtensions":                                                      "NRCGI-ExtIEs",
	"NRCapacityValue.IEExtensions":                                            "NRCapacityValue-ExtIEs",
	"NRCarrierItem.IEExtension":                                               "NRCarrierItem-ExtIEs",
	"NRCompositeAvailableCapacity.IEExtensions":                               "NRCompositeAvailableCapacity-ExtIEs",
	"NRCompositeAvailableCapacityGroup.IEExtensions":                          "NRCompositeAvailableCapacityGroup-ExtIEs",
	"NRFreqInfo.IEExtensions":                                                 "NRFreqInfo-ExtIEs",
	"NRNeighbourInformationElem.IEExtensions":                                 "NRNeighbour-Information-ExtIEs",
	"NRRAReportListItem.IEExtensions":                                         "NRRAReportList-Item-ExtIEs",
	"NRRadioResourceStatus.IEExtensions":                                      "NRRadioResourceStatus-ExtIEs",
	"NRTxBW.IEExtensions":                                                     "NR-TxBW-ExtIEs",
	"NRUESecurityCapabilities.IEExtensions":                                   "NRUESecurityCapabilities-ExtIEs",
	"NRUESidelinkAggregateMaximumBitRate.IEExtensions":                        "NRUESidelinkAggregateMaximumBitRate-ExtIEs",
	"NRUeReport.IEExtensions":                                                 "NRUeReport-ExtIEs",
	"NRV2XServicesAuthorized.IEExtensions":                                    "NRV2XServicesAuthorized-ExtIEs",
	"NeighbourInformationElem.IEExtensions":                                   "Neighbour-Information-ExtIEs",
	"NonAnchorCarrierFrequencylistElem.IEExtensions":                          "Non-AnchorCarrierFrequencylist-ExtIEs",
	"PC5FlowBitRates.IEExtensions":                                            "PC5FlowBitRates-ExtIEs",
	"PC5QoSFlowItem.IEExtensions":                                             "PC5QoSFlowItem-ExtIEs",
	"PC5QoSParameters.IEExtensions":                                           "PC5QoSParameters-ExtIEs",
	"PLMNAreaBasedQMC.IEExtensions":                                           "PLMNAreaBasedQMC-ExtIEs",
	"PRACHConfiguration.IEExtensions":                                         "PRACH-Configuration-ExtIEs",
	"ProSeAuthorized.IEExtensions":                                            "ProSeAuthorized-ExtIEs",
	"ProtectedEUTRAResourceIndication.IEExtensions":                           "ProtectedEUTRAResourceIndication-ExtIEs",
	"ProtectedFootprintTimePattern.IEExtensions":                              "ProtectedFootprintTimePattern-ExtIEs",
	"ProtectedResourceListItem.IEExtensions":                                  "ProtectedResourceList-Item-ExtIEs",
	"QoSMappingInformation.IEExtensions":                                      "QoS-Mapping-Information-ExtIEs",
	"RATRestrictionsItem.IEExtensions":                                        "RAT-RestrictionsItem-ExtIEs",
	"RLCStatus.IEExtensions":                                                  "RLC-Status-ExtIEs",
	"RNLHeader.IEExtensions":                                                  "RNL-Header-Item-ExtIEs",
	"RSRPMRListElem.IEExtensions":                                             "RSRPMRList-ExtIEs",
	"RSRPMeasurementResultElem.IEExtensions":                                  "RSRPMeasurementResult-ExtIEs",
	"RaReportIndicationListItem.IEExtensions":                                 "RaReportIndicationList-Item-ExtIEs",
	"RadioResourceStatus.IEExtensions":                                        "RadioResourceStatus-ExtIEs",
	"RelativeNarrowbandTxPower.IEExtensions":                                  "RelativeNarrowbandTxPower-ExtIEs",
	"ReservedSubframePattern.IEExtensions":                                    "ReservedSubframePattern-ExtIEs",
	"ResponseInformationSeNBReconfCompRejectByMeNBItem.IEExtensions":          "ResponseInformationSeNBReconfComp-RejectByMeNBItemExtIEs",
	"ResponseInformationSeNBReconfCompSuccessItem.IEExtensions":               "ResponseInformationSeNBReconfComp-SuccessItemExtIEs",
	"ResponseInformationSgNBReconfCompRejectByMeNBItem.IEExtensions":          "ResponseInformationSgNBReconfComp-RejectByMeNBItemExtIEs",
	"ResponseInformationSgNBReconfCompSuccessItem.IEExtensions":               "ResponseInformationSgNBReconfComp-SuccessItemExtIEs",
	"S1TNLLoadIndicator.IEExtensions":                                         "S1TNLLoadIndicator-ExtIEs",
	"SFNOffset.IEExtensions":                                                  "SFN-Offset-ExtIEs",
	"SSBAreaCapacityValueItem.IEExtensions":                                   "SSBAreaCapacityValue-ExtIEs",
	"SSBAreaRadioResourceStatusItem.IEExtensions":                             "SSBAreaRadioResourceStatus-ExtIEs",
	"SSBToReportItem.IEExtensions":                                            "SSBToReport-Item-ExtIEs",
	"SULInformation.IEExtensions":                                             "SULInformation-ExtIEs",
	"ScheduledCommunicationTime.IEExtensions":                                 "ScheduledCommunicationTime-ExtIEs",
	"SecondaryRATUsageReportItem.IEExtensions":                                "SecondaryRATUsageReport-Item-ExtIEs",
	"SecurityIndication.IEExtensions":                                         "SecurityIndication-ExtIEs",
	"SecurityResult.IEExtensions":                                             "SecurityResult-ExtIEs",
	"SensorMeasConfigNameItem.IEExtensions":                                   "SensorMeasConfigNameItem-ExtIEs",
	"SensorMeasurementConfiguration.IEExtensions":                             "SensorMeasurementConfiguration-ExtIEs",
	"ServedCellInformation.IEExtensions":                                      "ServedCell-Information-ExtIEs",
	"ServedCellSpecificInfoReqNRItem.IEExtensions":                            "ServedCellSpecificInfoReq-NR-Item-ExtIEs",
	"ServedCellsElem.IEExtensions":                                            "ServedCell-ExtIEs",
	"ServedCellsToActivateItem.IEExtensions":                                  "ServedCellsToActivate-Item-ExtIEs",
	"ServedCellsToModifyItem.IEExtensions":                                    "ServedCellsToModify-Item-ExtIEs",
	"ServedEUTRAcellsENDCX2ManagementListElem.IEExtensions":                   "ServedEUTRAcellsENDCX2Management-ExtIEs",
	"ServedEUTRAcellsToModifyListENDCConfUpdElem.IEExtensions":                "ServedEUTRAcellsToModifyListENDCConfUpd-ExtIEs",
	"ServedNRCellInformation.IEExtensions":                                    "ServedNRCell-Information-ExtIEs",
	"ServedNRCellsToActivateItem.IEExtensions":                                "ServedNRCellsToActivate-Item-ExtIEs",
	"ServedNRCellsToModifyItem.IEExtensions":                                  "ServedNRCellsToModify-Item-ExtIEs",
	"ServedNRcellsENDCX2ManagementListElem.IEExtensions":                      "En-gNBServedCells-ExtIEs",
	"SgNBResourceCoordinationInformation.IEExtensions":                        "SgNBResourceCoordinationInformationExtIEs",
	"SpecialSubframeInfo.IEExtensions":                                        "SpecialSubframe-Info-ExtIEs",
	"SplitSRB.IEExtensions":                                                   "SplitSRB-ExtIEs",
	"SubbandCQI.IEExtensions":                                                 "SubbandCQI-ExtIEs",
	"SubbandCQIItem.IEExtensions":                                             "SubbandCQIItem-ExtIEs",
	"SubscriptionBasedUEDifferentiationInfo.IEExtensions":                     "Subscription-Based-UE-DifferentiationInfo-ExtIEs",
	"SupportedSULFreqBandItem.IEExtensions":                                   "SupportedSULFreqBandItem-ExtIEs",
	"TABasedMDT.IEExtensions":                                                 "TABasedMDT-ExtIEs",
	"TABasedQMC.IEExtensions":                                                 "TABasedQMC-ExtIEs",
	"TAIBasedMDT.IEExtensions":                                                "TAIBasedMDT-ExtIEs",
	"TAIBasedQMC.IEExtensions":                                                "TAIBasedQMC-ExtIEs",
	"TAIItem.IEExtensions":                                                    "TAI-Item-ExtIEs",
	"TDDInfo.IEExtensions":                                                    "TDD-Info-ExtIEs",
	"TDDInfoNeighbourServedNRCellInformation.IEExtensions":                    "TDD-InfoNeighbourServedNRCell-Information-ExtIEs",
	"TDDInfoServedNRCellInformation.IEExtensions":                             "TDD-InfoServedNRCell-Information-ExtIEs",
	"TNLAFailedToSetupItem.IEExtensions":                                      "TNLA-Failed-To-Setup-Item-ExtIEs",
	"TNLASetupItem.IEExtensions":                                              "TNLA-Setup-Item-ExtIEs",
	"TNLAToAddItem.IEExtensions":                                              "TNLA-To-Add-Item-ExtIEs",
	"TNLAToRemoveItem.IEExtensions":                                           "TNLA-To-Remove-Item-ExtIEs",
	"TNLAToUpdateItem.IEExtensions":                                           "TNLA-To-Update-Item-ExtIEs",
	"TNLCapacityIndicator.IEExtensions":                                       "TNLCapacityIndicator-ExtIEs",
	"TNLConfigurationInfo.IEExtensions":                                       "TNLConfigurationInfo-ExtIEs",
	"TraceActivation.IEExtensions":                                            "TraceActivation-ExtIEs",
	"TransportUPLayerAddressesInfoToAddItem.IEExtensions":                     "Transport-UP-Layer-Addresses-Info-To-Add-ItemExtIEs",
	"TransportUPLayerAddressesInfoToRemoveItem.IEExtensions":                  "Transport-UP-Layer-Addresses-Info-To-Remove-ItemExtIEs",
	"TunnelInformation.IEExtensions":                                          "Tunnel-Information-ExtIEs",
	"UEAggregateMaximumBitRate.IEExtensions":                                  "UEAggregate-MaximumBitrate-ExtIEs",
	"UEAppLayerMeasConfig.IEExtensions":                                       "UEAppLayerMeasConfig-ExtIEs",
	"UEContextInformation.IEExtensions":                                       "UE-ContextInformation-ExtIEs",
	"UEContextInformationRetrieve.IEExtensions":                               "UE-ContextInformationRetrieve-ExtIEs",
	"UEContextInformationSeNBModReq.IEExtensions":                             "UE-ContextInformationSeNBModReqExtIEs",
	"UEContextInformationSgNBModReq.IEExtensions":                             "UE-ContextInformationSgNBModReqExtIEs",
	"UEContextReferenceAtSeNB.IEExtensions":                                   "UE-ContextReferenceAtSeNB-ItemExtIEs",
	"UEContextReferenceAtSgNB.IEExtensions":                                   "UE-ContextReferenceAtSgNB-ItemExtIEs",
	"UEContextReferenceAtWT.IEExtensions":                                     "UE-ContextReferenceAtWT-ItemExtIEs",
	"UESecurityCapabilities.IEExtensions":                                     "UESecurityCapabilities-ExtIEs",
	"UESidelinkAggregateMaximumBitRate.IEExtensions":                          "UE-Sidelink-Aggregate-MaximumBitRate-ExtIEs",
	"UEsToBeResetListItem.IEExtensions":                                       "UEsToBeResetList-Item-ExtIEs",
	"ULConfiguration.IEExtensions":                                            "ULConfiguration-ExtIEs",
	"ULHighInterferenceIndicationInfoItem.IEExtensions":                       "UL-HighInterferenceIndicationInfo-Item-ExtIEs",
	"ULOnlySharing.IEExtensions":                                              "ULOnlySharing-ExtIEs",
	"ULandDLSharing.IEExtensions":                                             "ULandDLSharing-ExtIEs",
	"UsableABSInformationFDD.IEExtensions":                                    "UsableABSInformationFDD-ExtIEs",
	"UsableABSInformationTDD.IEExtensions":                                    "UsableABSInformationTDD-ExtIEs",
	"V2XServicesAuthorized.IEExtensions":                                      "V2XServicesAuthorized-ExtIEs",
	"WLANMeasurementConfiguration.IEExtensions":                               "WLANMeasurementConfiguration-ExtIEs",
	"WidebandCQI.IEExtensions":                                                "WidebandCQI-ExtIEs",
}

var protocolExtensionTypeObjectSets = map[string]string{}

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

// DecodeValueRecursive decodes the selected X2APPDU outcome and every nested protocol open type.
func (v *X2APPDU) DecodeValueRecursive() (*DecodedProtocolValue, error) {
	if v == nil {
		return nil, fmt.Errorf("cannot recursively decode nil X2APPDU")
	}
	switch v.Choice {
	case X2APPDUChoiceInitiatingMessage:
		if v.InitiatingMessage == nil {
			return nil, fmt.Errorf("X2APPDU initiatingMessage alternative is nil")
		}
		return v.InitiatingMessage.DecodeValueRecursive()
	case X2APPDUChoiceSuccessfulOutcome:
		if v.SuccessfulOutcome == nil {
			return nil, fmt.Errorf("X2APPDU successfulOutcome alternative is nil")
		}
		return v.SuccessfulOutcome.DecodeValueRecursive()
	case X2APPDUChoiceUnsuccessfulOutcome:
		if v.UnsuccessfulOutcome == nil {
			return nil, fmt.Errorf("X2APPDU unsuccessfulOutcome alternative is nil")
		}
		return v.UnsuccessfulOutcome.DecodeValueRecursive()
	default:
		return nil, fmt.Errorf("unknown X2APPDU choice %d", v.Choice)
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
