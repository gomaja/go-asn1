// Code generated from ASN.1. DO NOT EDIT.

package lppa

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
	case 2: // id-e-CIDMeasurementInitiation
		var v ECIDMeasurementInitiationRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ECIDMeasurementInitiationRequest: %w", err)
		}
		return &v, nil
	case 3: // id-e-CIDMeasurementFailureIndication
		var v ECIDMeasurementFailureIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ECIDMeasurementFailureIndication: %w", err)
		}
		return &v, nil
	case 4: // id-e-CIDMeasurementReport
		var v ECIDMeasurementReport
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ECIDMeasurementReport: %w", err)
		}
		return &v, nil
	case 5: // id-e-CIDMeasurementTermination
		var v ECIDMeasurementTerminationCommand
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ECIDMeasurementTerminationCommand: %w", err)
		}
		return &v, nil
	case 6: // id-oTDOAInformationExchange
		var v OTDOAInformationRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding OTDOAInformationRequest: %w", err)
		}
		return &v, nil
	case 7: // id-uTDOAInformationExchange
		var v UTDOAInformationRequest
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UTDOAInformationRequest: %w", err)
		}
		return &v, nil
	case 8: // id-uTDOAInformationUpdate
		var v UTDOAInformationUpdate
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UTDOAInformationUpdate: %w", err)
		}
		return &v, nil
	case 9: // id-assistanceInformationControl
		var v AssistanceInformationControl
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding AssistanceInformationControl: %w", err)
		}
		return &v, nil
	case 10: // id-assistanceInformationFeedback
		var v AssistanceInformationFeedback
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding AssistanceInformationFeedback: %w", err)
		}
		return &v, nil
	case 0: // id-errorIndication
		var v ErrorIndication
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ErrorIndication: %w", err)
		}
		return &v, nil
	case 1: // id-privateMessage
		var v PrivateMessage
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding PrivateMessage: %w", err)
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
	case 2: // id-e-CIDMeasurementInitiation
		var v ECIDMeasurementInitiationResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ECIDMeasurementInitiationResponse: %w", err)
		}
		return &v, nil
	case 6: // id-oTDOAInformationExchange
		var v OTDOAInformationResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding OTDOAInformationResponse: %w", err)
		}
		return &v, nil
	case 7: // id-uTDOAInformationExchange
		var v UTDOAInformationResponse
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UTDOAInformationResponse: %w", err)
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
	case 2: // id-e-CIDMeasurementInitiation
		var v ECIDMeasurementInitiationFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding ECIDMeasurementInitiationFailure: %w", err)
		}
		return &v, nil
	case 6: // id-oTDOAInformationExchange
		var v OTDOAInformationFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding OTDOAInformationFailure: %w", err)
		}
		return &v, nil
	case 7: // id-uTDOAInformationExchange
		var v UTDOAInformationFailure
		if err := v.UnmarshalAPERFrom(bb); err != nil {
			return nil, fmt.Errorf("decoding UTDOAInformationFailure: %w", err)
		}
		return &v, nil
	default:
		return nil, nil
	}
}

// DecodeIEFieldValue decodes a known IE open value using its object-set context and ID.
// Returns the decoded typed value, or nil if the combination is unknown.
func DecodeIEFieldValue(objectSet string, ieId int64, data []byte) (interface{}, error) {
	switch objectSet {
	case "InterRATMeasurementQuantities-ItemIEs":
		switch ieId {
		case 16: // id-InterRATMeasurementQuantities-Item -> InterRATMeasurementQuantitiesItem
			var v InterRATMeasurementQuantitiesItem
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE InterRATMeasurementQuantitiesItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "MeasurementQuantities-ItemIEs":
		switch ieId {
		case 11: // id-MeasurementQuantities-Item -> MeasurementQuantitiesItem
			var v MeasurementQuantitiesItem
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementQuantitiesItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "WLANMeasurementQuantities-ItemIEs":
		switch ieId {
		case 20: // id-WLANMeasurementQuantities-Item -> WLANMeasurementQuantitiesItem
			var v WLANMeasurementQuantitiesItem
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE WLANMeasurementQuantitiesItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-CIDMeasurementInitiationRequest-IEs":
		switch ieId {
		case 2: // id-E-SMLC-UE-Measurement-ID -> MeasurementID (INTEGER)
			bb := per.NewBitBufferFromBytes(data)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("15"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		case 3: // id-ReportCharacteristics -> ReportCharacteristics (ENUMERATED)
			bb := per.NewBitBufferFromBytes(data)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE ReportCharacteristics (%d): %w", ieId, err)
			}
			result := ReportCharacteristics(v)
			return &result, nil
		case 4: // id-MeasurementPeriodicity -> MeasurementPeriodicity (ENUMERATED)
			bb := per.NewBitBufferFromBytes(data)
			v, err := per.DecodeEnumeratedAligned(bb, 13, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementPeriodicity (%d): %w", ieId, err)
			}
			result := MeasurementPeriodicity(v)
			return &result, nil
		case 5: // id-MeasurementQuantities -> MeasurementQuantities (SEQUENCE_OF)
			v, err := UnmarshalAPERMeasurementQuantities(data)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementQuantities (%d): %w", ieId, err)
			}
			return &v, nil
		case 15: // id-InterRATMeasurementQuantities -> InterRATMeasurementQuantities (SEQUENCE_OF)
			v, err := UnmarshalAPERInterRATMeasurementQuantities(data)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterRATMeasurementQuantities (%d): %w", ieId, err)
			}
			return &v, nil
		case 19: // id-WLANMeasurementQuantities -> WLANMeasurementQuantities (SEQUENCE_OF)
			v, err := UnmarshalAPERWLANMeasurementQuantities(data)
			if err != nil {
				return nil, fmt.Errorf("decoding IE WLANMeasurementQuantities (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-CIDMeasurementInitiationResponse-IEs":
		switch ieId {
		case 2: // id-E-SMLC-UE-Measurement-ID -> MeasurementID (INTEGER)
			bb := per.NewBitBufferFromBytes(data)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("15"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		case 6: // id-eNB-UE-Measurement-ID -> MeasurementID (INTEGER)
			bb := per.NewBitBufferFromBytes(data)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("15"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		case 7: // id-E-CID-MeasurementResult -> ECIDMeasurementResult
			var v ECIDMeasurementResult
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE ECIDMeasurementResult (%d): %w", ieId, err)
			}
			return &v, nil
		case 1: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 14: // id-Cell-Portion-ID -> CellPortionID (INTEGER)
			bb := per.NewBitBufferFromBytes(data)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellPortionID (%d): %w", ieId, err)
			}
			return v, nil
		case 17: // id-InterRATMeasurementResult -> InterRATMeasurementResult (SEQUENCE_OF)
			v, err := UnmarshalAPERInterRATMeasurementResult(data)
			if err != nil {
				return nil, fmt.Errorf("decoding IE InterRATMeasurementResult (%d): %w", ieId, err)
			}
			return &v, nil
		case 21: // id-WLANMeasurementResult -> WLANMeasurementResult (SEQUENCE_OF)
			v, err := UnmarshalAPERWLANMeasurementResult(data)
			if err != nil {
				return nil, fmt.Errorf("decoding IE WLANMeasurementResult (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-CIDMeasurementInitiationFailure-IEs":
		switch ieId {
		case 2: // id-E-SMLC-UE-Measurement-ID -> MeasurementID (INTEGER)
			bb := per.NewBitBufferFromBytes(data)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("15"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		case 0: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 1: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-CIDMeasurementFailureIndication-IEs":
		switch ieId {
		case 2: // id-E-SMLC-UE-Measurement-ID -> MeasurementID (INTEGER)
			bb := per.NewBitBufferFromBytes(data)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("15"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		case 6: // id-eNB-UE-Measurement-ID -> MeasurementID (INTEGER)
			bb := per.NewBitBufferFromBytes(data)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("15"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		case 0: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "E-CIDMeasurementReport-IEs":
		switch ieId {
		case 2: // id-E-SMLC-UE-Measurement-ID -> MeasurementID (INTEGER)
			bb := per.NewBitBufferFromBytes(data)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("15"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		case 6: // id-eNB-UE-Measurement-ID -> MeasurementID (INTEGER)
			bb := per.NewBitBufferFromBytes(data)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("15"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		case 7: // id-E-CID-MeasurementResult -> ECIDMeasurementResult
			var v ECIDMeasurementResult
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE ECIDMeasurementResult (%d): %w", ieId, err)
			}
			return &v, nil
		case 14: // id-Cell-Portion-ID -> CellPortionID (INTEGER)
			bb := per.NewBitBufferFromBytes(data)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("0"), runtime.MustParseBigIntDecimal("255"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE CellPortionID (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "E-CIDMeasurementTerminationCommand-IEs":
		switch ieId {
		case 2: // id-E-SMLC-UE-Measurement-ID -> MeasurementID (INTEGER)
			bb := per.NewBitBufferFromBytes(data)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("15"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		case 6: // id-eNB-UE-Measurement-ID -> MeasurementID (INTEGER)
			bb := per.NewBitBufferFromBytes(data)
			v, err := per.DecodeIntegerBigBoundsAligned(bb, runtime.MustParseBigIntDecimal("1"), runtime.MustParseBigIntDecimal("15"), true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE MeasurementID (%d): %w", ieId, err)
			}
			return v, nil
		}
	case "OTDOAInformationRequest-IEs":
		switch ieId {
		case 9: // id-OTDOA-Information-Type-Group -> OTDOAInformationType (SEQUENCE_OF)
			v, err := UnmarshalAPEROTDOAInformationType(data)
			if err != nil {
				return nil, fmt.Errorf("decoding IE OTDOAInformationType (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "OTDOA-Information-TypeIEs":
		switch ieId {
		case 10: // id-OTDOA-Information-Type-Item -> OTDOAInformationTypeItem
			var v OTDOAInformationTypeItem
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE OTDOAInformationTypeItem (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "OTDOAInformationResponse-IEs":
		switch ieId {
		case 8: // id-OTDOACells -> OTDOACells (SEQUENCE_OF)
			v, err := UnmarshalAPEROTDOACells(data)
			if err != nil {
				return nil, fmt.Errorf("decoding IE OTDOACells (%d): %w", ieId, err)
			}
			return &v, nil
		case 1: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		case 18: // id-AddOTDOACells -> AddOTDOACells (SEQUENCE_OF)
			v, err := UnmarshalAPERAddOTDOACells(data)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AddOTDOACells (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "OTDOAInformationFailure-IEs":
		switch ieId {
		case 0: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 1: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UTDOAInformationRequest-IEs":
		switch ieId {
		case 12: // id-RequestedSRSTransmissionCharacteristics -> RequestedSRSTransmissionCharacteristics
			var v RequestedSRSTransmissionCharacteristics
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE RequestedSRSTransmissionCharacteristics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UTDOAInformationResponse-IEs":
		switch ieId {
		case 13: // id-ULConfiguration -> ULConfiguration
			var v ULConfiguration
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE ULConfiguration (%d): %w", ieId, err)
			}
			return &v, nil
		case 1: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UTDOAInformationFailure-IEs":
		switch ieId {
		case 0: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 1: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "UTDOAInformationUpdate-IEs":
		switch ieId {
		case 13: // id-ULConfiguration -> ULConfiguration
			var v ULConfiguration
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE ULConfiguration (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "AssistanceInformationControl-IEs":
		switch ieId {
		case 22: // id-Assistance-Information -> AssistanceInformation
			var v AssistanceInformation
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE AssistanceInformation (%d): %w", ieId, err)
			}
			return &v, nil
		case 23: // id-Broadcast -> Broadcast (ENUMERATED)
			bb := per.NewBitBufferFromBytes(data)
			v, err := per.DecodeEnumeratedAligned(bb, 2, true)
			if err != nil {
				return nil, fmt.Errorf("decoding IE Broadcast (%d): %w", ieId, err)
			}
			result := Broadcast(v)
			return &result, nil
		}
	case "AssistanceInformationFeedback-IEs":
		switch ieId {
		case 24: // id-AssistanceInformationFailureList -> AssistanceInformationFailureList (SEQUENCE_OF)
			v, err := UnmarshalAPERAssistanceInformationFailureList(data)
			if err != nil {
				return nil, fmt.Errorf("decoding IE AssistanceInformationFailureList (%d): %w", ieId, err)
			}
			return &v, nil
		case 1: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	case "ErrorIndication-IEs":
		switch ieId {
		case 0: // id-Cause -> Cause
			var v Cause
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE Cause (%d): %w", ieId, err)
			}
			return &v, nil
		case 1: // id-CriticalityDiagnostics -> CriticalityDiagnostics
			var v CriticalityDiagnostics
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding IE CriticalityDiagnostics (%d): %w", ieId, err)
			}
			return &v, nil
		}
	}
	return nil, nil
}

// DecodeExtensionFieldValue decodes a known extension open value using its object-set context and ID.
// Returns the decoded typed value, or nil if the combination is unknown.
func DecodeExtensionFieldValue(objectSet string, extensionId int64, data []byte) (interface{}, error) {
	switch objectSet {
	case "ResultNR-Item-ExtIEs":
		switch extensionId {
		case 25: // id-ResultsPerSSB-Index-List -> ResultsPerSSBIndexList (SEQUENCE_OF)
			v, err := UnmarshalAPERResultsPerSSBIndexList(data)
			if err != nil {
				return nil, fmt.Errorf("decoding extension ResultsPerSSBIndexList (%d): %w", extensionId, err)
			}
			return &v, nil
		case 27: // id-NR-CGI -> NRCGI
			var v NRCGI
			if err := v.UnmarshalAPER(data); err != nil {
				return nil, fmt.Errorf("decoding extension NRCGI (%d): %w", extensionId, err)
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
	"AssistanceInformationControl.ProtocolIEs":      "AssistanceInformationControl-IEs",
	"AssistanceInformationFeedback.ProtocolIEs":     "AssistanceInformationFeedback-IEs",
	"ECIDMeasurementFailureIndication.ProtocolIEs":  "E-CIDMeasurementFailureIndication-IEs",
	"ECIDMeasurementInitiationFailure.ProtocolIEs":  "E-CIDMeasurementInitiationFailure-IEs",
	"ECIDMeasurementInitiationRequest.ProtocolIEs":  "E-CIDMeasurementInitiationRequest-IEs",
	"ECIDMeasurementInitiationResponse.ProtocolIEs": "E-CIDMeasurementInitiationResponse-IEs",
	"ECIDMeasurementReport.ProtocolIEs":             "E-CIDMeasurementReport-IEs",
	"ECIDMeasurementTerminationCommand.ProtocolIEs": "E-CIDMeasurementTerminationCommand-IEs",
	"ErrorIndication.ProtocolIEs":                   "ErrorIndication-IEs",
	"OTDOAInformationFailure.ProtocolIEs":           "OTDOAInformationFailure-IEs",
	"OTDOAInformationRequest.ProtocolIEs":           "OTDOAInformationRequest-IEs",
	"OTDOAInformationResponse.ProtocolIEs":          "OTDOAInformationResponse-IEs",
	"UTDOAInformationFailure.ProtocolIEs":           "UTDOAInformationFailure-IEs",
	"UTDOAInformationRequest.ProtocolIEs":           "UTDOAInformationRequest-IEs",
	"UTDOAInformationResponse.ProtocolIEs":          "UTDOAInformationResponse-IEs",
	"UTDOAInformationUpdate.ProtocolIEs":            "UTDOAInformationUpdate-IEs",
}

var protocolIETypeObjectSets = map[string]string{
	"InterRATMeasurementQuantities": "InterRATMeasurementQuantities-ItemIEs",
	"MeasurementQuantities":         "MeasurementQuantities-ItemIEs",
	"OTDOAInformationType":          "OTDOA-Information-TypeIEs",
	"WLANMeasurementQuantities":     "WLANMeasurementQuantities-ItemIEs",
}

var protocolExtensionFieldObjectSets = map[string]string{
	"AddOTDOACellsElem.IEExtensions":                    "Add-OTDOACells-ExtIEs",
	"AssistanceInformation.IEExtensions":                "Assistance-Information-ExtIEs",
	"AssistanceInformationFailureListElem.IEExtensions": "AssistanceInformationFailureList-ExtIEs",
	"AssistanceInformationMetaData.IEExtensions":        "AssistanceInformationMetaData-ExtIEs",
	"CriticalityDiagnostics.IEExtensions":               "CriticalityDiagnostics-ExtIEs",
	"CriticalityDiagnosticsIEListElem.IEExtensions":     "CriticalityDiagnostics-IE-List-ExtIEs",
	"ECGI.IEExtensions":                                 "ECGI-ExtIEs",
	"InterRATMeasurementQuantitiesItem.IEExtensions":    "InterRATMeasurementQuantitiesValue-ExtIEs",
	"MeasurementQuantitiesItem.IEExtensions":            "MeasurementQuantitiesValue-ExtIEs",
	"NRCGI.IEExtensions":                                "NR-CGI-ExtIEs",
	"OTDOACellsElem.IEExtensions":                       "OTDOACells-ExtIEs",
	"OTDOAInformationTypeItem.IEExtensions":             "OTDOA-Information-Type-ItemExtIEs",
	"PRSFrequencyHoppingConfiguration.IEExtensions":     "PRSFrequencyHoppingConfiguration-Item-IEs",
	"PosSIBSegmentsElem.IEExtensions":                   "PosSIB-Segments-ExtIEs",
	"PosSIBsElem.IEExtensions":                          "PosSIBs-ExtIEs",
	"ResultGERANItem.IEExtensions":                      "ResultGERAN-Item-ExtIEs",
	"ResultNRItem.IEExtensions":                         "ResultNR-Item-ExtIEs",
	"ResultRSRPItem.IEExtensions":                       "ResultRSRP-Item-ExtIEs",
	"ResultRSRQItem.IEExtensions":                       "ResultRSRQ-Item-ExtIEs",
	"ResultUTRANItem.IEExtensions":                      "ResultUTRAN-Item-ExtIEs",
	"ResultsPerSSBIndexItem.IEExtensions":               "ResultsPerSSB-Index-Item-ExtIEs",
	"SystemInformationElem.IEExtensions":                "SystemInformation-ExtIEs",
	"TDDConfiguration.IEExtensions":                     "TDDConfiguration-ExtIEs",
	"WLANMeasurementQuantitiesItem.IEExtensions":        "WLANMeasurementQuantitiesValue-ExtIEs",
	"WLANMeasurementResultItem.IEExtensions":            "WLANMeasurementResult-Item-ExtIEs",
}

var protocolExtensionTypeObjectSets = map[string]string{}

func protocolIEValueTypeHint(objectSet string, id int64) protocolOpenTypeHint {
	switch objectSet {
	case "E-CIDMeasurementInitiationRequest-IEs":
		switch id {
		case 5:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "MeasurementQuantities-ItemIEs", typeName: "MeasurementQuantities"}
		case 15:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "InterRATMeasurementQuantities-ItemIEs", typeName: "InterRATMeasurementQuantities"}
		case 19:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "WLANMeasurementQuantities-ItemIEs", typeName: "WLANMeasurementQuantities"}
		}
	case "OTDOAInformationRequest-IEs":
		switch id {
		case 9:
			return protocolOpenTypeHint{family: "protocolIE", objectSet: "OTDOA-Information-TypeIEs", typeName: "OTDOAInformationType"}
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
	if value.IsValid() && value.Kind() == reflect.Struct && value.Type().NumField() == 2 &&
		len(value.Type().Name()) > len("Complete") && value.Type().Name()[len(value.Type().Name())-len("Complete"):] == "Complete" {
		payload, padding := value.FieldByName("Value"), value.FieldByName("PERPadding_")
		if payload.IsValid() && padding.IsValid() && padding.Type() == reflect.TypeOf(per.CompletePadding{}) {
			return payload
		}
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
	if unwrapped := indirectProtocolOpenTypeValue(value); unwrapped.IsValid() && unwrapped.Type() != value.Type() {
		return decodeProtocolFieldsInValue(unwrapped, hint, path, seen)
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

// DecodeValueRecursive decodes the selected LPPAPDU outcome and every nested protocol open type.
func (v *LPPAPDU) DecodeValueRecursive() (*DecodedProtocolValue, error) {
	if v == nil {
		return nil, fmt.Errorf("cannot recursively decode nil LPPAPDU")
	}
	switch v.Choice {
	case LPPAPDUChoiceInitiatingMessage:
		if v.InitiatingMessage == nil {
			return nil, fmt.Errorf("LPPAPDU initiatingMessage alternative is nil")
		}
		return v.InitiatingMessage.DecodeValueRecursive()
	case LPPAPDUChoiceSuccessfulOutcome:
		if v.SuccessfulOutcome == nil {
			return nil, fmt.Errorf("LPPAPDU successfulOutcome alternative is nil")
		}
		return v.SuccessfulOutcome.DecodeValueRecursive()
	case LPPAPDUChoiceUnsuccessfulOutcome:
		if v.UnsuccessfulOutcome == nil {
			return nil, fmt.Errorf("LPPAPDU unsuccessfulOutcome alternative is nil")
		}
		return v.UnsuccessfulOutcome.DecodeValueRecursive()
	default:
		return nil, fmt.Errorf("unknown LPPAPDU choice %d", v.Choice)
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
