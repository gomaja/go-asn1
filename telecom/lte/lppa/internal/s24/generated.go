// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s24 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s24

import (
	q7 "fmt"
	q16 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q19 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q6 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	q18 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s14"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s15"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s16"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s17"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s18"
	q20 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s20"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s22"
	q17 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s23"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

func NewECIDMeasurementInitiationRequest(fields q4.ECIDMeasurementInitiationRequestIEContainer, options ...q5.BuildOption) (q4.ECIDMeasurementInitiationRequest, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q4.ECIDMeasurementInitiationRequest{}, q5.OperationError(err, "ECIDMeasurementInitiationRequest")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q4.ECIDMeasurementInitiationRequestIEField](bb, uint64(len(fields))); err != nil {
		return q4.ECIDMeasurementInitiationRequest{}, q5.OperationError(err, "ECIDMeasurementInitiationRequest")
	}
	v := q4.ECIDMeasurementInitiationRequest{ProtocolIEs: make(q4.ECIDMeasurementInitiationRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateECIDMeasurementInitiationRequestBudget(&v, budget)
	if err != nil {
		return q4.ECIDMeasurementInitiationRequest{}, q5.OperationError(err, "ECIDMeasurementInitiationRequest")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return q4.ECIDMeasurementInitiationRequest{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "ECIDMeasurementInitiationRequest")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q4.ECIDMeasurementInitiationRequest{}, q5.OperationError(&q6.BuildError{Issues: issues}, "ECIDMeasurementInitiationRequest")
	}
	if _, err := q4.BridgeECIDMeasurementInitiationRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q4.ECIDMeasurementInitiationRequest{}, q5.OperationError(q7.Errorf("%s %w", "ECIDMeasurementInitiationRequest.protocolIEs:", err), "ECIDMeasurementInitiationRequest")
	}
	return v, q5.OperationError(nil, "ECIDMeasurementInitiationRequest")
}
func NewECIDMeasurementInitiationResponse(fields q8.ECIDMeasurementInitiationResponseIEContainer, options ...q5.BuildOption) (q8.ECIDMeasurementInitiationResponse, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q8.ECIDMeasurementInitiationResponse{}, q5.OperationError(err, "ECIDMeasurementInitiationResponse")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q8.ECIDMeasurementInitiationResponseIEField](bb, uint64(len(fields))); err != nil {
		return q8.ECIDMeasurementInitiationResponse{}, q5.OperationError(err, "ECIDMeasurementInitiationResponse")
	}
	v := q8.ECIDMeasurementInitiationResponse{ProtocolIEs: make(q8.ECIDMeasurementInitiationResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateECIDMeasurementInitiationResponseBudget(&v, budget)
	if err != nil {
		return q8.ECIDMeasurementInitiationResponse{}, q5.OperationError(err, "ECIDMeasurementInitiationResponse")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return q8.ECIDMeasurementInitiationResponse{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "ECIDMeasurementInitiationResponse")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q8.ECIDMeasurementInitiationResponse{}, q5.OperationError(&q6.BuildError{Issues: issues}, "ECIDMeasurementInitiationResponse")
	}
	if _, err := q8.BridgeECIDMeasurementInitiationResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q8.ECIDMeasurementInitiationResponse{}, q5.OperationError(q7.Errorf("%s %w", "ECIDMeasurementInitiationResponse.protocolIEs:", err), "ECIDMeasurementInitiationResponse")
	}
	return v, q5.OperationError(nil, "ECIDMeasurementInitiationResponse")
}
func NewOTDOAInformationResponse(fields q9.OTDOAInformationResponseIEContainer, options ...q5.BuildOption) (q9.OTDOAInformationResponse, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q9.OTDOAInformationResponse{}, q5.OperationError(err, "OTDOAInformationResponse")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q9.OTDOAInformationResponseIEField](bb, uint64(len(fields))); err != nil {
		return q9.OTDOAInformationResponse{}, q5.OperationError(err, "OTDOAInformationResponse")
	}
	v := q9.OTDOAInformationResponse{ProtocolIEs: make(q9.OTDOAInformationResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateOTDOAInformationResponseBudget(&v, budget)
	if err != nil {
		return q9.OTDOAInformationResponse{}, q5.OperationError(err, "OTDOAInformationResponse")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return q9.OTDOAInformationResponse{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "OTDOAInformationResponse")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q9.OTDOAInformationResponse{}, q5.OperationError(&q6.BuildError{Issues: issues}, "OTDOAInformationResponse")
	}
	if _, err := q9.BridgeOTDOAInformationResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q9.OTDOAInformationResponse{}, q5.OperationError(q7.Errorf("%s %w", "OTDOAInformationResponse.protocolIEs:", err), "OTDOAInformationResponse")
	}
	return v, q5.OperationError(nil, "OTDOAInformationResponse")
}
func NewUTDOAInformationRequest(fields q6.UTDOAInformationRequestIEContainer, options ...q5.BuildOption) (q10.UTDOAInformationRequest, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q10.UTDOAInformationRequest{}, q5.OperationError(err, "UTDOAInformationRequest")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q6.UTDOAInformationRequestIEField](bb, uint64(len(fields))); err != nil {
		return q10.UTDOAInformationRequest{}, q5.OperationError(err, "UTDOAInformationRequest")
	}
	v := q10.UTDOAInformationRequest{ProtocolIEs: make(q6.UTDOAInformationRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUTDOAInformationRequestBudget(&v, budget)
	if err != nil {
		return q10.UTDOAInformationRequest{}, q5.OperationError(err, "UTDOAInformationRequest")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return q10.UTDOAInformationRequest{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "UTDOAInformationRequest")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q10.UTDOAInformationRequest{}, q5.OperationError(&q6.BuildError{Issues: issues}, "UTDOAInformationRequest")
	}
	if _, err := q10.BridgeUTDOAInformationRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q10.UTDOAInformationRequest{}, q5.OperationError(q7.Errorf("%s %w", "UTDOAInformationRequest.protocolIEs:", err), "UTDOAInformationRequest")
	}
	return v, q5.OperationError(nil, "UTDOAInformationRequest")
}
func NewUTDOAInformationResponse(fields q11.UTDOAInformationResponseIEContainer, options ...q5.BuildOption) (q12.UTDOAInformationResponse, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q12.UTDOAInformationResponse{}, q5.OperationError(err, "UTDOAInformationResponse")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q11.UTDOAInformationResponseIEField](bb, uint64(len(fields))); err != nil {
		return q12.UTDOAInformationResponse{}, q5.OperationError(err, "UTDOAInformationResponse")
	}
	v := q12.UTDOAInformationResponse{ProtocolIEs: make(q11.UTDOAInformationResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUTDOAInformationResponseBudget(&v, budget)
	if err != nil {
		return q12.UTDOAInformationResponse{}, q5.OperationError(err, "UTDOAInformationResponse")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return q12.UTDOAInformationResponse{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "UTDOAInformationResponse")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q12.UTDOAInformationResponse{}, q5.OperationError(&q6.BuildError{Issues: issues}, "UTDOAInformationResponse")
	}
	if _, err := q12.BridgeUTDOAInformationResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q12.UTDOAInformationResponse{}, q5.OperationError(q7.Errorf("%s %w", "UTDOAInformationResponse.protocolIEs:", err), "UTDOAInformationResponse")
	}
	return v, q5.OperationError(nil, "UTDOAInformationResponse")
}
func NewUTDOAInformationFailure(fields q11.UTDOAInformationFailureIEContainer, options ...q5.BuildOption) (q10.UTDOAInformationFailure, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q10.UTDOAInformationFailure{}, q5.OperationError(err, "UTDOAInformationFailure")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q11.UTDOAInformationFailureIEField](bb, uint64(len(fields))); err != nil {
		return q10.UTDOAInformationFailure{}, q5.OperationError(err, "UTDOAInformationFailure")
	}
	v := q10.UTDOAInformationFailure{ProtocolIEs: make(q11.UTDOAInformationFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUTDOAInformationFailureBudget(&v, budget)
	if err != nil {
		return q10.UTDOAInformationFailure{}, q5.OperationError(err, "UTDOAInformationFailure")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return q10.UTDOAInformationFailure{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "UTDOAInformationFailure")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q10.UTDOAInformationFailure{}, q5.OperationError(&q6.BuildError{Issues: issues}, "UTDOAInformationFailure")
	}
	if _, err := q10.BridgeUTDOAInformationFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q10.UTDOAInformationFailure{}, q5.OperationError(q7.Errorf("%s %w", "UTDOAInformationFailure.protocolIEs:", err), "UTDOAInformationFailure")
	}
	return v, q5.OperationError(nil, "UTDOAInformationFailure")
}
func NewUTDOAInformationUpdate(fields q13.UTDOAInformationUpdateIEContainer, options ...q5.BuildOption) (q12.UTDOAInformationUpdate, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q12.UTDOAInformationUpdate{}, q5.OperationError(err, "UTDOAInformationUpdate")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q13.UTDOAInformationUpdateIEField](bb, uint64(len(fields))); err != nil {
		return q12.UTDOAInformationUpdate{}, q5.OperationError(err, "UTDOAInformationUpdate")
	}
	v := q12.UTDOAInformationUpdate{ProtocolIEs: make(q13.UTDOAInformationUpdateIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUTDOAInformationUpdateBudget(&v, budget)
	if err != nil {
		return q12.UTDOAInformationUpdate{}, q5.OperationError(err, "UTDOAInformationUpdate")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return q12.UTDOAInformationUpdate{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "UTDOAInformationUpdate")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q12.UTDOAInformationUpdate{}, q5.OperationError(&q6.BuildError{Issues: issues}, "UTDOAInformationUpdate")
	}
	if _, err := q12.BridgeUTDOAInformationUpdateMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q12.UTDOAInformationUpdate{}, q5.OperationError(q7.Errorf("%s %w", "UTDOAInformationUpdate.protocolIEs:", err), "UTDOAInformationUpdate")
	}
	return v, q5.OperationError(nil, "UTDOAInformationUpdate")
}
func NewAssistanceInformationControl(fields q14.AssistanceInformationControlIEContainer, options ...q5.BuildOption) (q15.AssistanceInformationControl, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q15.AssistanceInformationControl{}, q5.OperationError(err, "AssistanceInformationControl")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q14.AssistanceInformationControlIEField](bb, uint64(len(fields))); err != nil {
		return q15.AssistanceInformationControl{}, q5.OperationError(err, "AssistanceInformationControl")
	}
	v := q15.AssistanceInformationControl{ProtocolIEs: make(q14.AssistanceInformationControlIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateAssistanceInformationControlBudget(&v, budget)
	if err != nil {
		return q15.AssistanceInformationControl{}, q5.OperationError(err, "AssistanceInformationControl")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return q15.AssistanceInformationControl{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "AssistanceInformationControl")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q15.AssistanceInformationControl{}, q5.OperationError(&q6.BuildError{Issues: issues}, "AssistanceInformationControl")
	}
	if _, err := q15.BridgeAssistanceInformationControlMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q15.AssistanceInformationControl{}, q5.OperationError(q7.Errorf("%s %w", "AssistanceInformationControl.protocolIEs:", err), "AssistanceInformationControl")
	}
	return v, q5.OperationError(nil, "AssistanceInformationControl")
}
func (ECIDMeasurementInitiationDescriptor) Initiating() q4.ECIDMeasurementInitiationRequestInitiatingBinding {
	return func() q4.ECIDMeasurementInitiationRequestInitiatingBinding {
		sealed := q4.ECIDMeasurementInitiationRequestInitiatingBinding{}
		*q4.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldInfo(&sealed) = ECIDMeasurementInitiationProcedure().Info()
		*q4.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldValidate(&sealed) = func(v *q4.ECIDMeasurementInitiationRequest, budget *q5.DecodeBudget) (q6.ValidationReport, error) {
			return BridgeValidateECIDMeasurementInitiationRequestBudget(v, budget)
		}
		*q4.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldEncode(&sealed) = func(v *q4.ECIDMeasurementInitiationRequest, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q4.BridgeECIDMeasurementInitiationRequestMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q4.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.ECIDMeasurementInitiationRequest, error) {
			var v q4.ECIDMeasurementInitiationRequest
			err := q4.BridgeECIDMeasurementInitiationRequestMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q4.ECIDMeasurementInitiationRequest{}, err
			}
			*q4.BridgeECIDMeasurementInitiationRequestFieldReceived(&v) = true
			*q4.BridgeECIDMeasurementInitiationRequestFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q4.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldInject(&sealed) = func(v q4.ECIDMeasurementInitiationRequest) q4.InitiatingValue {
			return func() q4.InitiatingValue {
				sealed := q4.InitiatingValue{}
				*q4.BridgeInitiatingValueFieldCode(&sealed) = q16.ProcedureCode(2)
				*q4.BridgeInitiatingValueFieldBodyECIDMeasurementInitiationRequest(&sealed) = &v
				return sealed
			}()
		}
		*q4.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldCapture(&sealed) = func(v q4.ECIDMeasurementInitiationRequest, options q5.DecodeState) (q4.ECIDMeasurementInitiationRequest, q5.Snapshot,
		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaECIDMeasurementInitiationRequest(&v, &s)
			var root q5.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q4.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldCompare(&sealed) = func(v q4.ECIDMeasurementInitiationRequest, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q4.BridgeCompareLPPaECIDMeasurementInitiationRequest(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldContext(&sealed) = func() q16.BridgeCodecContext {
			sealed := q16.BridgeCodecContext{}
			*q16.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementInitiationRequest"
			return sealed
		}()
		return sealed
	}()

}
func (ECIDMeasurementInitiationDescriptor) Successful() q17.ECIDMeasurementInitiationResponseSuccessfulBinding {
	return func() q17.ECIDMeasurementInitiationResponseSuccessfulBinding {
		sealed := q17.ECIDMeasurementInitiationResponseSuccessfulBinding{}
		*q17.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldInfo(&sealed) = ECIDMeasurementInitiationProcedure().Info()
		*q17.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldValidate(&sealed) = func(v *q8.ECIDMeasurementInitiationResponse, budget *q5.DecodeBudget) (q6.ValidationReport, error) {
			return BridgeValidateECIDMeasurementInitiationResponseBudget(v, budget)
		}
		*q17.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldEncode(&sealed) = func(v *q8.ECIDMeasurementInitiationResponse, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q8.BridgeECIDMeasurementInitiationResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q17.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q8.ECIDMeasurementInitiationResponse, error) {
			var v q8.ECIDMeasurementInitiationResponse
			err := q8.BridgeECIDMeasurementInitiationResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q8.ECIDMeasurementInitiationResponse{}, err
			}
			*q8.BridgeECIDMeasurementInitiationResponseFieldReceived(&v) = true
			*q8.BridgeECIDMeasurementInitiationResponseFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q17.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldInject(&sealed) = func(v q8.ECIDMeasurementInitiationResponse) q8.SuccessfulValue {
			return func() q8.SuccessfulValue {
				sealed := q8.SuccessfulValue{}
				*q8.BridgeSuccessfulValueFieldCode(&sealed) = q16.ProcedureCode(2)
				*q8.BridgeSuccessfulValueFieldBodyECIDMeasurementInitiationResponse(&sealed) = &v
				return sealed
			}()
		}
		*q17.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldCapture(&sealed) = func(v q8.ECIDMeasurementInitiationResponse, options q5.DecodeState) (q8.ECIDMeasurementInitiationResponse, q5.Snapshot,

		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q8.BridgeCaptureLPPaECIDMeasurementInitiationResponse(&v, &s)
			var root q5.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q17.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldCompare(&sealed) = func(v q8.ECIDMeasurementInitiationResponse, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q8.BridgeCompareLPPaECIDMeasurementInitiationResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q17.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldContext(&sealed) = func() q16.BridgeCodecContext {
			sealed := q16.BridgeCodecContext{}
			*q16.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementInitiationResponse"
			return sealed
		}()
		return sealed
	}()

}
func (ECIDMeasurementInitiationDescriptor) Unsuccessful() q10.ECIDMeasurementInitiationFailureUnsuccessfulBinding {
	return func() q10.ECIDMeasurementInitiationFailureUnsuccessfulBinding {
		sealed := q10.ECIDMeasurementInitiationFailureUnsuccessfulBinding{}
		*q10.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldInfo(&sealed) = ECIDMeasurementInitiationProcedure().Info()
		*q10.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *q13.ECIDMeasurementInitiationFailure, budget *q5.DecodeBudget) (q6.ValidationReport, error) {
			return q17.BridgeValidateECIDMeasurementInitiationFailureBudget(v, budget)
		}
		*q10.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *q13.ECIDMeasurementInitiationFailure, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q13.BridgeECIDMeasurementInitiationFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q10.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q13.ECIDMeasurementInitiationFailure, error) {
			var v q13.ECIDMeasurementInitiationFailure
			err := q13.BridgeECIDMeasurementInitiationFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q13.ECIDMeasurementInitiationFailure{}, err
			}
			*q13.BridgeECIDMeasurementInitiationFailureFieldReceived(&v) = true
			*q13.BridgeECIDMeasurementInitiationFailureFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q10.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldInject(&sealed) = func(v q13.ECIDMeasurementInitiationFailure) q10.UnsuccessfulValue {
			return func() q10.UnsuccessfulValue {
				sealed := q10.UnsuccessfulValue{}
				*q10.BridgeUnsuccessfulValueFieldCode(&sealed) = q16.ProcedureCode(2)
				*q10.BridgeUnsuccessfulValueFieldBodyECIDMeasurementInitiationFailure(&sealed) = &v
				return sealed
			}()
		}
		*q10.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v q13.ECIDMeasurementInitiationFailure, options q5.DecodeState) (q13.ECIDMeasurementInitiationFailure, q5.Snapshot,
		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q13.BridgeCaptureLPPaECIDMeasurementInitiationFailure(&v, &s)
			var root q5.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q10.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v q13.ECIDMeasurementInitiationFailure, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q13.BridgeCompareLPPaECIDMeasurementInitiationFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q10.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldContext(&sealed) = func() q16.BridgeCodecContext {
			sealed := q16.BridgeCodecContext{}
			*q16.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementInitiationFailure"
			return sealed
		}()
		return sealed
	}()

}
func (OTDOAInformationExchangeDescriptor) Initiating() q4.OTDOAInformationRequestInitiatingBinding {
	return func() q4.OTDOAInformationRequestInitiatingBinding {
		sealed := q4.OTDOAInformationRequestInitiatingBinding{}
		*q4.BridgeOTDOAInformationRequestInitiatingBindingFieldInfo(&sealed) = OTDOAInformationExchangeProcedure().Info()
		*q4.BridgeOTDOAInformationRequestInitiatingBindingFieldValidate(&sealed) = func(v *q9.OTDOAInformationRequest, budget *q5.DecodeBudget) (q6.ValidationReport, error) {
			return q17.BridgeValidateOTDOAInformationRequestBudget(v, budget)
		}
		*q4.BridgeOTDOAInformationRequestInitiatingBindingFieldEncode(&sealed) = func(v *q9.OTDOAInformationRequest, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q9.BridgeOTDOAInformationRequestMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q4.BridgeOTDOAInformationRequestInitiatingBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q9.OTDOAInformationRequest, error) {
			var v q9.OTDOAInformationRequest
			err := q9.BridgeOTDOAInformationRequestMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q9.OTDOAInformationRequest{}, err
			}
			*q9.BridgeOTDOAInformationRequestFieldReceived(&v) = true
			*q9.BridgeOTDOAInformationRequestFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q4.BridgeOTDOAInformationRequestInitiatingBindingFieldInject(&sealed) = func(v q9.OTDOAInformationRequest) q4.InitiatingValue {
			return func() q4.InitiatingValue {
				sealed := q4.InitiatingValue{}
				*q4.BridgeInitiatingValueFieldCode(&sealed) = q16.ProcedureCode(6)
				*q4.BridgeInitiatingValueFieldBodyOTDOAInformationRequest(&sealed) = &v
				return sealed
			}()
		}
		*q4.BridgeOTDOAInformationRequestInitiatingBindingFieldCapture(&sealed) = func(v q9.OTDOAInformationRequest, options q5.DecodeState) (q9.OTDOAInformationRequest, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q9.BridgeCaptureLPPaOTDOAInformationRequest(
				&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*q4.BridgeOTDOAInformationRequestInitiatingBindingFieldCompare(&sealed) = func(v q9.OTDOAInformationRequest, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q9.BridgeCompareLPPaOTDOAInformationRequest(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeOTDOAInformationRequestInitiatingBindingFieldContext(&sealed) = func() q16.BridgeCodecContext {
			sealed := q16.BridgeCodecContext{}
			*q16.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOAInformationRequest"
			return sealed
		}()
		return sealed
	}()

}
func (OTDOAInformationExchangeDescriptor) Successful() q17.OTDOAInformationResponseSuccessfulBinding {
	return func() q17.OTDOAInformationResponseSuccessfulBinding {
		sealed := q17.OTDOAInformationResponseSuccessfulBinding{}
		*q17.BridgeOTDOAInformationResponseSuccessfulBindingFieldInfo(&sealed) = OTDOAInformationExchangeProcedure().Info()
		*q17.BridgeOTDOAInformationResponseSuccessfulBindingFieldValidate(&sealed) = func(v *q9.OTDOAInformationResponse, budget *q5.DecodeBudget) (q6.ValidationReport, error) {
			return BridgeValidateOTDOAInformationResponseBudget(v, budget)
		}
		*q17.BridgeOTDOAInformationResponseSuccessfulBindingFieldEncode(&sealed) = func(v *q9.OTDOAInformationResponse, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q9.BridgeOTDOAInformationResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q17.BridgeOTDOAInformationResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q9.OTDOAInformationResponse, error) {
			var v q9.OTDOAInformationResponse
			err := q9.BridgeOTDOAInformationResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q9.OTDOAInformationResponse{}, err
			}
			*q9.BridgeOTDOAInformationResponseFieldReceived(&v) = true
			*q9.BridgeOTDOAInformationResponseFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q17.BridgeOTDOAInformationResponseSuccessfulBindingFieldInject(&sealed) = func(v q9.OTDOAInformationResponse) q8.SuccessfulValue {
			return func() q8.SuccessfulValue {
				sealed := q8.SuccessfulValue{}
				*q8.BridgeSuccessfulValueFieldCode(&sealed) = q16.ProcedureCode(6)
				*q8.BridgeSuccessfulValueFieldBodyOTDOAInformationResponse(&sealed) = &v
				return sealed
			}()
		}
		*q17.BridgeOTDOAInformationResponseSuccessfulBindingFieldCapture(&sealed) = func(v q9.OTDOAInformationResponse, options q5.DecodeState) (q9.OTDOAInformationResponse, q5.Snapshot,
		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q9.BridgeCaptureLPPaOTDOAInformationResponse(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q17.BridgeOTDOAInformationResponseSuccessfulBindingFieldCompare(&sealed) = func(v q9.OTDOAInformationResponse, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q9.BridgeCompareLPPaOTDOAInformationResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q17.BridgeOTDOAInformationResponseSuccessfulBindingFieldContext(&sealed) = func() q16.BridgeCodecContext {
			sealed := q16.BridgeCodecContext{}
			*q16.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOAInformationResponse"
			return sealed
		}()
		return sealed
	}()

}
func (OTDOAInformationExchangeDescriptor) Unsuccessful() q10.OTDOAInformationFailureUnsuccessfulBinding {
	return func() q10.OTDOAInformationFailureUnsuccessfulBinding {
		sealed := q10.OTDOAInformationFailureUnsuccessfulBinding{}
		*q10.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldInfo(&sealed) = OTDOAInformationExchangeProcedure().Info()
		*q10.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *q18.OTDOAInformationFailure, budget *q5.DecodeBudget) (q6.ValidationReport, error) {
			return q17.BridgeValidateOTDOAInformationFailureBudget(v, budget)
		}
		*q10.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *q18.OTDOAInformationFailure, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q18.BridgeOTDOAInformationFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q10.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q18.OTDOAInformationFailure, error) {
			var v q18.OTDOAInformationFailure
			err := q18.BridgeOTDOAInformationFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q18.OTDOAInformationFailure{}, err
			}
			*q18.BridgeOTDOAInformationFailureFieldReceived(&v) = true
			*q18.BridgeOTDOAInformationFailureFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q10.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldInject(&sealed) = func(v q18.OTDOAInformationFailure) q10.UnsuccessfulValue {
			return func() q10.UnsuccessfulValue {
				sealed := q10.UnsuccessfulValue{}
				*q10.BridgeUnsuccessfulValueFieldCode(&sealed) = q16.ProcedureCode(6)
				*q10.BridgeUnsuccessfulValueFieldBodyOTDOAInformationFailure(&sealed) = &v
				return sealed
			}()
		}
		*q10.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v q18.OTDOAInformationFailure, options q5.DecodeState) (q18.OTDOAInformationFailure, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q18.BridgeCaptureLPPaOTDOAInformationFailure(
				&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*q10.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v q18.OTDOAInformationFailure, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q18.BridgeCompareLPPaOTDOAInformationFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q10.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldContext(&sealed) = func() q16.BridgeCodecContext {
			sealed := q16.BridgeCodecContext{}
			*q16.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOAInformationFailure"
			return sealed
		}()
		return sealed
	}()

}
func (UTDOAInformationExchangeDescriptor) Initiating() q4.UTDOAInformationRequestInitiatingBinding {
	return func() q4.UTDOAInformationRequestInitiatingBinding {
		sealed := q4.UTDOAInformationRequestInitiatingBinding{}
		*q4.BridgeUTDOAInformationRequestInitiatingBindingFieldInfo(&sealed) = UTDOAInformationExchangeProcedure().Info()
		*q4.BridgeUTDOAInformationRequestInitiatingBindingFieldValidate(&sealed) = func(v *q10.UTDOAInformationRequest, budget *q5.DecodeBudget) (q6.ValidationReport, error) {
			return BridgeValidateUTDOAInformationRequestBudget(v, budget)
		}
		*q4.BridgeUTDOAInformationRequestInitiatingBindingFieldEncode(&sealed) = func(v *q10.UTDOAInformationRequest, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q10.BridgeUTDOAInformationRequestMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q4.BridgeUTDOAInformationRequestInitiatingBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q10.UTDOAInformationRequest, error) {
			var v q10.UTDOAInformationRequest
			err := q10.BridgeUTDOAInformationRequestMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q10.UTDOAInformationRequest{}, err
			}
			*q10.BridgeUTDOAInformationRequestFieldReceived(&v) = true
			*q10.BridgeUTDOAInformationRequestFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q4.BridgeUTDOAInformationRequestInitiatingBindingFieldInject(&sealed) = func(v q10.UTDOAInformationRequest) q4.InitiatingValue {
			return func() q4.InitiatingValue {
				sealed := q4.InitiatingValue{}
				*q4.BridgeInitiatingValueFieldCode(&sealed) = q16.ProcedureCode(7)
				*q4.BridgeInitiatingValueFieldBodyUTDOAInformationRequest(&sealed) = &v
				return sealed
			}()
		}
		*q4.BridgeUTDOAInformationRequestInitiatingBindingFieldCapture(&sealed) = func(v q10.UTDOAInformationRequest, options q5.DecodeState) (q10.UTDOAInformationRequest, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q10.BridgeCaptureLPPaUTDOAInformationRequest(
				&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*q4.BridgeUTDOAInformationRequestInitiatingBindingFieldCompare(&sealed) = func(v q10.UTDOAInformationRequest, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q10.BridgeCompareLPPaUTDOAInformationRequest(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeUTDOAInformationRequestInitiatingBindingFieldContext(&sealed) = func() q16.BridgeCodecContext {
			sealed := q16.BridgeCodecContext{}
			*q16.BridgecodecContextFieldSource(&sealed) = "source-value:UTDOAInformationRequest"
			return sealed
		}()
		return sealed
	}()

}
func (UTDOAInformationExchangeDescriptor) Successful() q17.UTDOAInformationResponseSuccessfulBinding {
	return func() q17.UTDOAInformationResponseSuccessfulBinding {
		sealed := q17.UTDOAInformationResponseSuccessfulBinding{}
		*q17.BridgeUTDOAInformationResponseSuccessfulBindingFieldInfo(&sealed) = UTDOAInformationExchangeProcedure().Info()
		*q17.BridgeUTDOAInformationResponseSuccessfulBindingFieldValidate(&sealed) = func(v *q12.UTDOAInformationResponse, budget *q5.DecodeBudget) (q6.ValidationReport, error) {
			return BridgeValidateUTDOAInformationResponseBudget(v, budget)
		}
		*q17.BridgeUTDOAInformationResponseSuccessfulBindingFieldEncode(&sealed) = func(v *q12.UTDOAInformationResponse, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q12.BridgeUTDOAInformationResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q17.BridgeUTDOAInformationResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q12.UTDOAInformationResponse, error) {
			var v q12.UTDOAInformationResponse
			err := q12.BridgeUTDOAInformationResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q12.UTDOAInformationResponse{}, err
			}
			*q12.BridgeUTDOAInformationResponseFieldReceived(&v) = true
			*q12.BridgeUTDOAInformationResponseFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q17.BridgeUTDOAInformationResponseSuccessfulBindingFieldInject(&sealed) = func(v q12.UTDOAInformationResponse) q8.SuccessfulValue {
			return func() q8.SuccessfulValue {
				sealed := q8.SuccessfulValue{}
				*q8.BridgeSuccessfulValueFieldCode(&sealed) = q16.ProcedureCode(7)
				*q8.BridgeSuccessfulValueFieldBodyUTDOAInformationResponse(&sealed) = &v
				return sealed
			}()
		}
		*q17.BridgeUTDOAInformationResponseSuccessfulBindingFieldCapture(&sealed) = func(v q12.UTDOAInformationResponse, options q5.DecodeState) (q12.UTDOAInformationResponse, q5.Snapshot,
		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q12.BridgeCaptureLPPaUTDOAInformationResponse(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q17.BridgeUTDOAInformationResponseSuccessfulBindingFieldCompare(&sealed) = func(v q12.UTDOAInformationResponse, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q12.BridgeCompareLPPaUTDOAInformationResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q17.BridgeUTDOAInformationResponseSuccessfulBindingFieldContext(&sealed) = func() q16.BridgeCodecContext {
			sealed := q16.BridgeCodecContext{}
			*q16.BridgecodecContextFieldSource(&sealed) = "source-value:UTDOAInformationResponse"
			return sealed
		}()
		return sealed
	}()

}
func (UTDOAInformationExchangeDescriptor) Unsuccessful() q10.UTDOAInformationFailureUnsuccessfulBinding {
	return func() q10.UTDOAInformationFailureUnsuccessfulBinding {
		sealed := q10.UTDOAInformationFailureUnsuccessfulBinding{}
		*q10.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldInfo(&sealed) = UTDOAInformationExchangeProcedure().Info()
		*q10.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *q10.UTDOAInformationFailure, budget *q5.DecodeBudget) (q6.ValidationReport, error) {
			return BridgeValidateUTDOAInformationFailureBudget(v, budget)
		}
		*q10.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *q10.UTDOAInformationFailure, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q10.BridgeUTDOAInformationFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q10.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q10.UTDOAInformationFailure, error) {
			var v q10.UTDOAInformationFailure
			err := q10.BridgeUTDOAInformationFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q10.UTDOAInformationFailure{}, err
			}
			*q10.BridgeUTDOAInformationFailureFieldReceived(&v) = true
			*q10.BridgeUTDOAInformationFailureFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q10.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldInject(&sealed) = func(v q10.UTDOAInformationFailure) q10.UnsuccessfulValue {
			return func() q10.UnsuccessfulValue {
				sealed := q10.UnsuccessfulValue{}
				*q10.BridgeUnsuccessfulValueFieldCode(&sealed) = q16.ProcedureCode(7)
				*q10.BridgeUnsuccessfulValueFieldBodyUTDOAInformationFailure(&sealed) = &v
				return sealed
			}()
		}
		*q10.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v q10.UTDOAInformationFailure, options q5.DecodeState) (q10.UTDOAInformationFailure, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q10.BridgeCaptureLPPaUTDOAInformationFailure(
				&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*q10.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v q10.UTDOAInformationFailure, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q10.BridgeCompareLPPaUTDOAInformationFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q10.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldContext(&sealed) = func() q16.BridgeCodecContext {
			sealed := q16.BridgeCodecContext{}
			*q16.BridgecodecContextFieldSource(&sealed) = "source-value:UTDOAInformationFailure"
			return sealed
		}()
		return sealed
	}()

}
func (UTDOAInformationUpdateDescriptor) Initiating() q4.UTDOAInformationUpdateInitiatingBinding {
	return func() q4.UTDOAInformationUpdateInitiatingBinding {
		sealed := q4.UTDOAInformationUpdateInitiatingBinding{}
		*q4.BridgeUTDOAInformationUpdateInitiatingBindingFieldInfo(&sealed) = UTDOAInformationUpdateProcedure().Info()
		*q4.BridgeUTDOAInformationUpdateInitiatingBindingFieldValidate(&sealed) = func(v *q12.UTDOAInformationUpdate, budget *q5.DecodeBudget) (q6.ValidationReport, error) {
			return BridgeValidateUTDOAInformationUpdateBudget(v, budget)
		}
		*q4.BridgeUTDOAInformationUpdateInitiatingBindingFieldEncode(&sealed) = func(v *q12.UTDOAInformationUpdate, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q12.BridgeUTDOAInformationUpdateMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q4.BridgeUTDOAInformationUpdateInitiatingBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q12.UTDOAInformationUpdate, error) {
			var v q12.UTDOAInformationUpdate
			err := q12.BridgeUTDOAInformationUpdateMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q12.UTDOAInformationUpdate{}, err
			}
			*q12.BridgeUTDOAInformationUpdateFieldReceived(&v) = true
			*q12.BridgeUTDOAInformationUpdateFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q4.BridgeUTDOAInformationUpdateInitiatingBindingFieldInject(&sealed) = func(v q12.UTDOAInformationUpdate) q4.InitiatingValue {
			return func() q4.InitiatingValue {
				sealed := q4.InitiatingValue{}
				*q4.BridgeInitiatingValueFieldCode(&sealed) = q16.ProcedureCode(8)
				*q4.BridgeInitiatingValueFieldBodyUTDOAInformationUpdate(&sealed) = &v
				return sealed
			}()
		}
		*q4.BridgeUTDOAInformationUpdateInitiatingBindingFieldCapture(&sealed) = func(v q12.UTDOAInformationUpdate, options q5.DecodeState) (q12.UTDOAInformationUpdate, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q12.BridgeCaptureLPPaUTDOAInformationUpdate(
				&v,

				&s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q4.BridgeUTDOAInformationUpdateInitiatingBindingFieldCompare(&sealed) = func(v q12.UTDOAInformationUpdate, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q12.BridgeCompareLPPaUTDOAInformationUpdate(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeUTDOAInformationUpdateInitiatingBindingFieldContext(&sealed) = func() q16.BridgeCodecContext {
			sealed := q16.BridgeCodecContext{}
			*q16.BridgecodecContextFieldSource(&sealed) = "source-value:UTDOAInformationUpdate"
			return sealed
		}()
		return sealed
	}()

}
func (AssistanceInformationControlDescriptor) Initiating() q4.AssistanceInformationControlInitiatingBinding {
	return func() q4.AssistanceInformationControlInitiatingBinding {
		sealed := q4.AssistanceInformationControlInitiatingBinding{}
		*q4.BridgeAssistanceInformationControlInitiatingBindingFieldInfo(&sealed) = AssistanceInformationControlProcedure().Info()
		*q4.BridgeAssistanceInformationControlInitiatingBindingFieldValidate(&sealed) = func(v *q15.AssistanceInformationControl, budget *q5.DecodeBudget) (q6.ValidationReport, error) {
			return BridgeValidateAssistanceInformationControlBudget(v, budget)
		}
		*q4.BridgeAssistanceInformationControlInitiatingBindingFieldEncode(&sealed) = func(v *q15.AssistanceInformationControl, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q15.BridgeAssistanceInformationControlMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q4.BridgeAssistanceInformationControlInitiatingBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q15.AssistanceInformationControl, error) {
			var v q15.AssistanceInformationControl
			err := q15.BridgeAssistanceInformationControlMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q15.AssistanceInformationControl{}, err
			}
			*q15.BridgeAssistanceInformationControlFieldReceived(&v) = true
			*q15.BridgeAssistanceInformationControlFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q4.BridgeAssistanceInformationControlInitiatingBindingFieldInject(&sealed) = func(v q15.AssistanceInformationControl) q4.InitiatingValue {
			return func() q4.InitiatingValue {
				sealed := q4.InitiatingValue{}
				*q4.BridgeInitiatingValueFieldCode(&sealed) = q16.ProcedureCode(9)
				*q4.BridgeInitiatingValueFieldBodyAssistanceInformationControl(&sealed) = &v
				return sealed
			}()
		}
		*q4.BridgeAssistanceInformationControlInitiatingBindingFieldCapture(&sealed) = func(v q15.AssistanceInformationControl, options q5.DecodeState) (q15.AssistanceInformationControl, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q15.BridgeCaptureLPPaAssistanceInformationControl(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q4.BridgeAssistanceInformationControlInitiatingBindingFieldCompare(&sealed) = func(v q15.AssistanceInformationControl, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q15.BridgeCompareLPPaAssistanceInformationControl(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}
		*q4.BridgeAssistanceInformationControlInitiatingBindingFieldContext(&sealed) = func() q16.BridgeCodecContext {
			sealed := q16.BridgeCodecContext{}
			*q16.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceInformationControl"
			return sealed
		}()
		return sealed
	}()

}

// NewLPPAPDUInitiatingMessage constructs and validates a complete LPPa message.
func NewLPPAPDUInitiatingMessage(v q4.InitiatingMessage, options ...q5.BuildOption) (q17.LPPAPDU, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q17.LPPAPDU{}, q5.OperationError(err, "LPPAPDUInitiatingMessage")
	}
	value := q17.BridgeNewLPPAPDUInitiatingMessageLegacy(v)
	report, err := BridgeValidateMessageBudget(&value, budget)
	if err != nil {
		return q17.LPPAPDU{}, q5.OperationError(err, "LPPAPDUInitiatingMessage")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return q17.LPPAPDU{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "LPPAPDUInitiatingMessage")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q17.LPPAPDU{}, q5.OperationError(&q6.BuildError{Issues: issues}, "LPPAPDUInitiatingMessage")
	}
	if _, err := q17.BridgeLPPAPDUMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q17.LPPAPDU{}, q5.OperationError(err, "LPPAPDUInitiatingMessage")
	}
	return value, q5.OperationError(nil, "LPPAPDUInitiatingMessage")
}

// NewLPPAPDUSuccessfulOutcome constructs and validates a complete LPPa message.
func NewLPPAPDUSuccessfulOutcome(v q8.SuccessfulOutcome, options ...q5.BuildOption) (q17.LPPAPDU, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q17.LPPAPDU{}, q5.OperationError(err, "LPPAPDUSuccessfulOutcome")
	}
	value := q17.BridgeNewLPPAPDUSuccessfulOutcomeLegacy(v)
	report, err := BridgeValidateMessageBudget(&value, budget)
	if err != nil {
		return q17.LPPAPDU{}, q5.OperationError(err, "LPPAPDUSuccessfulOutcome")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return q17.LPPAPDU{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "LPPAPDUSuccessfulOutcome")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q17.LPPAPDU{}, q5.OperationError(&q6.BuildError{Issues: issues}, "LPPAPDUSuccessfulOutcome")
	}
	if _, err := q17.BridgeLPPAPDUMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q17.LPPAPDU{}, q5.OperationError(err, "LPPAPDUSuccessfulOutcome")
	}
	return value, q5.OperationError(nil, "LPPAPDUSuccessfulOutcome")
}

// NewLPPAPDUUnsuccessfulOutcome constructs and validates a complete LPPa message.
func NewLPPAPDUUnsuccessfulOutcome(v q10.UnsuccessfulOutcome, options ...q5.BuildOption) (q17.LPPAPDU, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q17.LPPAPDU{}, q5.OperationError(err, "LPPAPDUUnsuccessfulOutcome")
	}
	value := q17.BridgeNewLPPAPDUUnsuccessfulOutcomeLegacy(v)
	report, err := BridgeValidateMessageBudget(&value, budget)
	if err != nil {
		return q17.LPPAPDU{}, q5.OperationError(err, "LPPAPDUUnsuccessfulOutcome")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return q17.LPPAPDU{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "LPPAPDUUnsuccessfulOutcome")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q17.LPPAPDU{}, q5.OperationError(&q6.BuildError{Issues: issues}, "LPPAPDUUnsuccessfulOutcome")
	}
	if _, err := q17.BridgeLPPAPDUMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q17.LPPAPDU{}, q5.OperationError(err, "LPPAPDUUnsuccessfulOutcome")
	}
	return value, q5.OperationError(nil, "LPPAPDUUnsuccessfulOutcome")
}

type ECIDMeasurementInitiationDescriptor struct{}

func ECIDMeasurementInitiationProcedure() ECIDMeasurementInitiationDescriptor {
	return ECIDMeasurementInitiationDescriptor{}
}
func (ECIDMeasurementInitiationDescriptor) Info() q16.ProcedureInfo {
	return q16.ProcedureInfo{Code: q16.ProcedureCode(2), Criticality: q16.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-e-CIDMeasurementInitiation"}}}
}

type OTDOAInformationExchangeDescriptor struct{}

func OTDOAInformationExchangeProcedure() OTDOAInformationExchangeDescriptor {
	return OTDOAInformationExchangeDescriptor{}
}
func (OTDOAInformationExchangeDescriptor) Info() q16.ProcedureInfo {
	return q16.ProcedureInfo{Code: q16.ProcedureCode(6), Criticality: q16.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-oTDOAInformationExchange"}}}
}

type UTDOAInformationExchangeDescriptor struct{}

func UTDOAInformationExchangeProcedure() UTDOAInformationExchangeDescriptor {
	return UTDOAInformationExchangeDescriptor{}
}
func (UTDOAInformationExchangeDescriptor) Info() q16.ProcedureInfo {
	return q16.ProcedureInfo{Code: q16.ProcedureCode(7), Criticality: q16.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-uTDOAInformationExchange"}}}
}

type UTDOAInformationUpdateDescriptor struct{}

func UTDOAInformationUpdateProcedure() UTDOAInformationUpdateDescriptor {
	return UTDOAInformationUpdateDescriptor{}
}
func (UTDOAInformationUpdateDescriptor) Info() q16.ProcedureInfo {
	return q16.ProcedureInfo{Code: q16.ProcedureCode(8), Criticality: q16.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-uTDOAInformationUpdate"}}}
}

type AssistanceInformationControlDescriptor struct{}

func AssistanceInformationControlProcedure() AssistanceInformationControlDescriptor {
	return AssistanceInformationControlDescriptor{}
}
func (AssistanceInformationControlDescriptor) Info() q16.ProcedureInfo {
	return q16.ProcedureInfo{Code: q16.ProcedureCode(9), Criticality: q16.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-assistanceInformationControl"}}}
}

// AssistanceInformationControlCodec binds the complete APER value type.
func AssistanceInformationControlCodec() q15.AssistanceInformationControlValueCodec {
	return AssistanceInformationControlProcedure().Initiating().Codec()
}

// ECIDMeasurementInitiationFailureCodec binds the complete APER value type.
func ECIDMeasurementInitiationFailureCodec() q13.ECIDMeasurementInitiationFailureValueCodec {
	return ECIDMeasurementInitiationProcedure().Unsuccessful().Codec()
}

// ECIDMeasurementInitiationRequestCodec binds the complete APER value type.
func ECIDMeasurementInitiationRequestCodec() q4.ECIDMeasurementInitiationRequestValueCodec {
	return ECIDMeasurementInitiationProcedure().Initiating().Codec()
}

// ECIDMeasurementInitiationResponseCodec binds the complete APER value type.
func ECIDMeasurementInitiationResponseCodec() q8.ECIDMeasurementInitiationResponseValueCodec {
	return ECIDMeasurementInitiationProcedure().Successful().Codec()
}

// OTDOAInformationFailureCodec binds the complete APER value type.
func OTDOAInformationFailureCodec() q18.OTDOAInformationFailureValueCodec {
	return OTDOAInformationExchangeProcedure().Unsuccessful().Codec()
}

// OTDOAInformationRequestCodec binds the complete APER value type.
func OTDOAInformationRequestCodec() q9.OTDOAInformationRequestValueCodec {
	return OTDOAInformationExchangeProcedure().Initiating().Codec()
}

// OTDOAInformationResponseCodec binds the complete APER value type.
func OTDOAInformationResponseCodec() q9.OTDOAInformationResponseValueCodec {
	return OTDOAInformationExchangeProcedure().Successful().Codec()
}

// UTDOAInformationFailureCodec binds the complete APER value type.
func UTDOAInformationFailureCodec() q10.UTDOAInformationFailureValueCodec {
	return UTDOAInformationExchangeProcedure().Unsuccessful().Codec()
}

// UTDOAInformationRequestCodec binds the complete APER value type.
func UTDOAInformationRequestCodec() q10.UTDOAInformationRequestValueCodec {
	return UTDOAInformationExchangeProcedure().Initiating().Codec()
}

// UTDOAInformationResponseCodec binds the complete APER value type.
func UTDOAInformationResponseCodec() q12.UTDOAInformationResponseValueCodec {
	return UTDOAInformationExchangeProcedure().Successful().Codec()
}

// UTDOAInformationUpdateCodec binds the complete APER value type.
func UTDOAInformationUpdateCodec() q12.UTDOAInformationUpdateValueCodec {
	return UTDOAInformationUpdateProcedure().Initiating().Codec()
}
func BridgeValidateECIDMeasurementInitiationRequestBudget(v *q4.ECIDMeasurementInitiationRequest, budget *q5.DecodeBudget,

) (q6.ValidationReport, error) {
	if v == nil {
		return func() q6.ValidationReport {
			sealed := q6.ValidationReport{}
			*q6.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q7.Errorf("nil ECIDMeasurementInitiationRequest")
	}
	rows := []q16.FieldInfo{q4.ECIDMeasurementInitiationRequestIEs().ESMLCUEMeasurementID().Info(), q4.ECIDMeasurementInitiationRequestIEs().ReportCharacteristics().Info(), q4.ECIDMeasurementInitiationRequestIEs().MeasurementPeriodicity().Info(), q4.ECIDMeasurementInitiationRequestIEs().MeasurementQuantities().Info(), q4.ECIDMeasurementInitiationRequestIEs().InterRATMeasurementQuantities().Info(), q4.ECIDMeasurementInitiationRequestIEs().WLANMeasurementQuantities().Info()}
	report := q4.BridgeECIDMeasurementInitiationRequestIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "ECIDMeasurementInitiationRequest.protocolIEs", budget)
	BridgeWalkValidationECIDMeasurementInitiationRequest(v, &report, "ECIDMeasurementInitiationRequest", true)
	return report, nil
}
func BridgeValidateECIDMeasurementInitiationResponseBudget(v *q8.ECIDMeasurementInitiationResponse, budget *q5.DecodeBudget,

) (q6.ValidationReport, error) {
	if v == nil {
		return func() q6.ValidationReport {
			sealed := q6.ValidationReport{}
			*q6.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q7.Errorf("nil ECIDMeasurementInitiationResponse")
	}
	rows := []q16.FieldInfo{q8.ECIDMeasurementInitiationResponseIEs().ESMLCUEMeasurementID().Info(), q8.ECIDMeasurementInitiationResponseIEs().ENBUEMeasurementID().Info(), q8.ECIDMeasurementInitiationResponseIEs().ECIDMeasurementResult().Info(), q8.ECIDMeasurementInitiationResponseIEs().CriticalityDiagnostics().Info(), q8.ECIDMeasurementInitiationResponseIEs().CellPortionID().Info(), q8.ECIDMeasurementInitiationResponseIEs().InterRATMeasurementResult().Info(), q8.ECIDMeasurementInitiationResponseIEs().WLANMeasurementResult().Info()}
	report := q17.BridgeECIDMeasurementInitiationResponseIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "ECIDMeasurementInitiationResponse.protocolIEs", budget)
	BridgeWalkValidationECIDMeasurementInitiationResponse(v, &report, "ECIDMeasurementInitiationResponse", true)
	return report, nil
}
func BridgeValidateOTDOAInformationResponseBudget(v *q9.OTDOAInformationResponse, budget *q5.DecodeBudget,

) (q6.ValidationReport, error) {
	if v == nil {
		return func() q6.ValidationReport {
			sealed := q6.ValidationReport{}
			*q6.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q7.Errorf("nil OTDOAInformationResponse")
	}
	rows := []q16.FieldInfo{q9.OTDOAInformationResponseIEs().OTDOACells().Info(), q9.OTDOAInformationResponseIEs().CriticalityDiagnostics().Info(), q9.OTDOAInformationResponseIEs().AddOTDOACells().Info()}
	report := q9.BridgeOTDOAInformationResponseIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "OTDOAInformationResponse.protocolIEs", budget)
	BridgeWalkValidationOTDOAInformationResponse(v, &report, "OTDOAInformationResponse", true)
	return report, nil
}
func BridgeValidateUTDOAInformationRequestBudget(v *q10.UTDOAInformationRequest, budget *q5.DecodeBudget,

) (q6.ValidationReport, error) {
	if v == nil {
		return func() q6.ValidationReport {
			sealed := q6.ValidationReport{}
			*q6.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q7.Errorf("nil UTDOAInformationRequest")
	}
	rows := []q16.FieldInfo{q6.UTDOAInformationRequestIEs().RequestedSRSTransmissionCharacteristics().Info()}
	report := q10.BridgeUTDOAInformationRequestIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "UTDOAInformationRequest.protocolIEs", budget)
	BridgeWalkValidationUTDOAInformationRequest(v, &report, "UTDOAInformationRequest", true)
	return report, nil
}
func BridgeValidateUTDOAInformationResponseBudget(v *q12.UTDOAInformationResponse, budget *q5.DecodeBudget,

) (q6.ValidationReport, error) {
	if v == nil {
		return func() q6.ValidationReport {
			sealed := q6.ValidationReport{}
			*q6.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q7.Errorf("nil UTDOAInformationResponse")
	}
	rows := []q16.FieldInfo{q11.UTDOAInformationResponseIEs().ULConfiguration().Info(), q11.UTDOAInformationResponseIEs().CriticalityDiagnostics().Info()}
	report := q12.BridgeUTDOAInformationResponseIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "UTDOAInformationResponse.protocolIEs", budget)
	BridgeWalkValidationUTDOAInformationResponse(v, &report, "UTDOAInformationResponse", true)
	return report, nil
}
func BridgeValidateUTDOAInformationFailureBudget(v *q10.UTDOAInformationFailure, budget *q5.DecodeBudget,

) (q6.ValidationReport, error) {
	if v == nil {
		return func() q6.ValidationReport {
			sealed := q6.ValidationReport{}
			*q6.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q7.Errorf("nil UTDOAInformationFailure")
	}
	rows := []q16.FieldInfo{q11.UTDOAInformationFailureIEs().Cause().Info(), q11.UTDOAInformationFailureIEs().CriticalityDiagnostics().Info()}
	report := q10.BridgeUTDOAInformationFailureIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "UTDOAInformationFailure.protocolIEs", budget)
	BridgeWalkValidationUTDOAInformationFailure(v, &report, "UTDOAInformationFailure", true)
	return report, nil
}
func BridgeValidateUTDOAInformationUpdateBudget(v *q12.UTDOAInformationUpdate, budget *q5.DecodeBudget,

) (q6.ValidationReport, error) {
	if v == nil {
		return func() q6.ValidationReport {
			sealed := q6.ValidationReport{}
			*q6.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q7.Errorf("nil UTDOAInformationUpdate")
	}
	rows := []q16.FieldInfo{q13.UTDOAInformationUpdateIEs().ULConfiguration().Info()}
	report := q12.BridgeUTDOAInformationUpdateIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "UTDOAInformationUpdate.protocolIEs", budget)
	BridgeWalkValidationUTDOAInformationUpdate(v, &report, "UTDOAInformationUpdate", true)
	return report, nil
}
func BridgeValidateAssistanceInformationControlBudget(v *q15.AssistanceInformationControl, budget *q5.DecodeBudget,

) (q6.ValidationReport, error) {
	if v == nil {
		return func() q6.ValidationReport {
			sealed := q6.ValidationReport{}
			*q6.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q7.Errorf("nil AssistanceInformationControl")
	}
	rows := []q16.FieldInfo{q14.AssistanceInformationControlIEs().AssistanceInformation().Info(), q14.AssistanceInformationControlIEs().Broadcast().Info()}
	report := q15.BridgeAssistanceInformationControlIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "AssistanceInformationControl.protocolIEs", budget)
	BridgeWalkValidationAssistanceInformationControl(v, &report, "AssistanceInformationControl", true)
	return report, nil
}
func BridgeValidateInitiatingMessage(v *q4.InitiatingMessage, budget *q5.DecodeBudget,

) (q6.ValidationReport, error) {
	if v == nil {
		return func() q6.ValidationReport {
			sealed := q6.ValidationReport{}
			*q6.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q7.Errorf("nil InitiatingMessage")
	}
	if *q4.BridgeInitiatingValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.ValueIDMismatch, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "InitiatingMessage.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.ValueIDMismatch), RelatedRules: []q5.SourceRule{{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "InitiatingMessage"}}}})
			return report
		}(), nil
	}
	switch v.ProcedureCode {
	case 0:
		body, ok := v.Value.AsErrorIndication()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing ErrorIndication", "InitiatingMessage.value:")
		}
		report, err := q17.BridgeValidateErrorIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityIgnore {
			expected, received := q16.CriticalityIgnore, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{q17.ErrorIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 1:
		body, ok := v.Value.AsPrivateMessage()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing PrivateMessage", "InitiatingMessage.value:")
		}
		report, err := q20.BridgeValidatePrivateMessageBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityIgnore {
			expected, received := q16.CriticalityIgnore, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{q4.PrivateMessageProcedure().Info().Rule}})
		}
		return report, nil
	case 2:
		body, ok := v.Value.AsECIDMeasurementInitiationRequest()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing ECIDMeasurementInitiationRequest", "InitiatingMessage.value:")
		}
		report, err := BridgeValidateECIDMeasurementInitiationRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityReject {
			expected, received := q16.CriticalityReject, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{ECIDMeasurementInitiationProcedure().Info().Rule}})
		}
		return report, nil
	case 3:
		body, ok := v.Value.AsECIDMeasurementFailureIndication()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing ECIDMeasurementFailureIndication", "InitiatingMessage.value:")
		}
		report, err := q17.BridgeValidateECIDMeasurementFailureIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityIgnore {
			expected, received := q16.CriticalityIgnore, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{q17.ECIDMeasurementFailureIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 4:
		body, ok := v.Value.AsECIDMeasurementReport()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing ECIDMeasurementReport", "InitiatingMessage.value:")
		}
		report, err := q17.BridgeValidateECIDMeasurementReportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityIgnore {
			expected, received := q16.CriticalityIgnore, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{q17.ECIDMeasurementReportProcedure().Info().Rule}})
		}
		return report, nil
	case 5:
		body, ok := v.Value.AsECIDMeasurementTerminationCommand()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing ECIDMeasurementTerminationCommand", "InitiatingMessage.value:")
		}
		report, err := q17.BridgeValidateECIDMeasurementTerminationCommandBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityReject {
			expected, received := q16.CriticalityReject, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{q17.ECIDMeasurementTerminationProcedure().Info().Rule}})
		}
		return report, nil
	case 6:
		body, ok := v.Value.AsOTDOAInformationRequest()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing OTDOAInformationRequest", "InitiatingMessage.value:")
		}
		report, err := q17.BridgeValidateOTDOAInformationRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityReject {
			expected, received := q16.CriticalityReject, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{OTDOAInformationExchangeProcedure().Info().Rule}})
		}
		return report, nil
	case 7:
		body, ok := v.Value.AsUTDOAInformationRequest()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing UTDOAInformationRequest", "InitiatingMessage.value:")
		}
		report, err := BridgeValidateUTDOAInformationRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityReject {
			expected, received := q16.CriticalityReject, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{UTDOAInformationExchangeProcedure().Info().Rule}})
		}
		return report, nil
	case 8:
		body, ok := v.Value.AsUTDOAInformationUpdate()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing UTDOAInformationUpdate", "InitiatingMessage.value:")
		}
		report, err := BridgeValidateUTDOAInformationUpdateBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityIgnore {
			expected, received := q16.CriticalityIgnore, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{UTDOAInformationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 9:
		body, ok := v.Value.AsAssistanceInformationControl()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing AssistanceInformationControl", "InitiatingMessage.value:")
		}
		report, err := BridgeValidateAssistanceInformationControlBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityReject {
			expected, received := q16.CriticalityReject, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{AssistanceInformationControlProcedure().Info().Rule}})
		}
		return report, nil
	case 10:
		body, ok := v.Value.AsAssistanceInformationFeedback()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing AssistanceInformationFeedback", "InitiatingMessage.value:")
		}
		report, err := q17.BridgeValidateAssistanceInformationFeedbackBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityReject {
			expected, received := q16.CriticalityReject, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{q17.AssistanceInformationFeedbackProcedure().Info().Rule}})
		}
		return report, nil
	default:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnknownProcedure, Severity: q16.ValidationSeverityUnrecognized, Location: q5.Location{Path: "InitiatingMessage.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnknownProcedure)})
			q6.BridgeValidationReportMethodAddUnchecked(&report, q5.Location{Path: "InitiatingMessage.value"})
			return report
		}(), nil
	}
}
func BridgeValidateSuccessfulOutcome(v *q8.SuccessfulOutcome, budget *q5.DecodeBudget,

) (q6.ValidationReport, error) {
	if v == nil {
		return func() q6.ValidationReport {
			sealed := q6.ValidationReport{}
			*q6.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q7.Errorf("nil SuccessfulOutcome")
	}
	if *q8.BridgeSuccessfulValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.ValueIDMismatch, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.ValueIDMismatch), RelatedRules: []q5.SourceRule{{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "SuccessfulOutcome"}}}})
			return report
		}(), nil
	}
	switch v.ProcedureCode {
	case 0:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	case 1:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	case 2:
		body, ok := v.Value.AsECIDMeasurementInitiationResponse()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing ECIDMeasurementInitiationResponse", "SuccessfulOutcome.value:")
		}
		report, err := BridgeValidateECIDMeasurementInitiationResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityReject {
			expected, received := q16.CriticalityReject, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{ECIDMeasurementInitiationProcedure().Info().Rule}})
		}
		return report, nil
	case 3:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	case 4:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	case 5:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	case 6:
		body, ok := v.Value.AsOTDOAInformationResponse()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing OTDOAInformationResponse", "SuccessfulOutcome.value:")
		}
		report, err := BridgeValidateOTDOAInformationResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityReject {
			expected, received := q16.CriticalityReject, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{OTDOAInformationExchangeProcedure().Info().Rule}})
		}
		return report, nil
	case 7:
		body, ok := v.Value.AsUTDOAInformationResponse()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing UTDOAInformationResponse", "SuccessfulOutcome.value:")
		}
		report, err := BridgeValidateUTDOAInformationResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityReject {
			expected, received := q16.CriticalityReject, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{UTDOAInformationExchangeProcedure().Info().Rule}})
		}
		return report, nil
	case 8:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	case 9:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	case 10:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	default:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnknownProcedure, Severity: q16.ValidationSeverityUnrecognized, Location: q5.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnknownProcedure)})
			q6.BridgeValidationReportMethodAddUnchecked(&report, q5.Location{Path: "SuccessfulOutcome.value"})
			return report
		}(), nil
	}
}
func BridgeValidateUnsuccessfulOutcome(v *q10.UnsuccessfulOutcome, budget *q5.DecodeBudget,

) (q6.ValidationReport, error) {
	if v == nil {
		return func() q6.ValidationReport {
			sealed := q6.ValidationReport{}
			*q6.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q7.Errorf("nil UnsuccessfulOutcome")
	}
	if *q10.BridgeUnsuccessfulValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.ValueIDMismatch, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.ValueIDMismatch), RelatedRules: []q5.SourceRule{{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "UnsuccessfulOutcome"}}}})
			return report
		}(), nil
	}
	switch v.ProcedureCode {
	case 0:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	case 1:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	case 2:
		body, ok := v.Value.AsECIDMeasurementInitiationFailure()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing ECIDMeasurementInitiationFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := q17.BridgeValidateECIDMeasurementInitiationFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityReject {
			expected, received := q16.CriticalityReject, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{ECIDMeasurementInitiationProcedure().Info().Rule}})
		}
		return report, nil
	case 3:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	case 4:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	case 5:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	case 6:
		body, ok := v.Value.AsOTDOAInformationFailure()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing OTDOAInformationFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := q17.BridgeValidateOTDOAInformationFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityReject {
			expected, received := q16.CriticalityReject, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{OTDOAInformationExchangeProcedure().Info().Rule}})
		}
		return report, nil
	case 7:
		body, ok := v.Value.AsUTDOAInformationFailure()
		if !ok {
			return func() q6.ValidationReport {
				sealed := q6.ValidationReport{}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), q7.Errorf("%s missing UTDOAInformationFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := BridgeValidateUTDOAInformationFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q6.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != q16.CriticalityReject {
			expected, received := q16.CriticalityReject, v.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.WrongCriticality, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q16.WrongCriticality), RelatedRules: []q5.SourceRule{UTDOAInformationExchangeProcedure().Info().Rule}})
		}
		return report, nil
	case 8:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	case 9:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	case 10:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnavailableOutcome, Severity: q16.ValidationSeverityError, Location: q5.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnavailableOutcome), RelatedRules: q19.BridgeLppaHandlingRules(q16.UnavailableOutcome)})
			return report
		}(), nil
	default:
		return func() q6.ValidationReport {
			report := func() q6.ValidationReport {
				sealed := q6.ValidationReport{Complete: false}
				*q6.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q16.UnknownProcedure, Severity: q16.ValidationSeverityUnrecognized, Location: q5.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: q19.BridgeLppaValidationRule(q16.UnknownProcedure)})
			q6.BridgeValidationReportMethodAddUnchecked(&report, q5.Location{Path: "UnsuccessfulOutcome.value"})
			return report
		}(), nil
	}
}
func BridgeValidateMessageBudget(v *q17.LPPAPDU, budget *q5.DecodeBudget,

) (q6.ValidationReport, error) {
	if v == nil {
		return func() q6.ValidationReport {
			sealed := q6.ValidationReport{}
			*q6.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q7.Errorf("nil LPPAPDU")
	}
	switch v.Choice {
	case q16.LPPAPDUChoiceInitiatingMessage:
		return BridgeValidateInitiatingMessage(v.InitiatingMessage, budget)
	case q16.LPPAPDUChoiceSuccessfulOutcome:
		return BridgeValidateSuccessfulOutcome(v.SuccessfulOutcome, budget)
	case q16.LPPAPDUChoiceUnsuccessfulOutcome:
		return BridgeValidateUnsuccessfulOutcome(v.UnsuccessfulOutcome, budget)
	default:
		if v.UnknownExtension != nil {
			return func() q6.ValidationReport {
				report := func() q6.ValidationReport {
					sealed := q6.ValidationReport{Complete: false}
					*q6.BridgeValidationReportFieldBudget(&sealed) = budget
					return sealed
				}()
				q6.BridgeValidationReportMethodAddUnchecked(&report, q5.Location{Path: "LPPAPDU.unknownExtension"})
				return report
			}(), nil
		}
		return func() q6.ValidationReport {
			sealed := q6.ValidationReport{}
			*q6.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q7.Errorf("%s invalid choice %d", "LPPAPDU:", v.Choice)
	}
}
func ValidateECIDMeasurementInitiationRequest(v *q4.ECIDMeasurementInitiationRequest, options ...q5.ValidationOption) (q6.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q6.ValidationReport{}, q5.OperationError(err, "ECIDMeasurementInitiationRequest")
	}
	report, err := BridgeValidateECIDMeasurementInitiationRequestBudget(v, budget)
	if err == nil && !q20.BridgeValidationHasValueMismatch(report) {
		_, err = q4.BridgeECIDMeasurementInitiationRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		err = *q6.BridgeValidationReportFieldErr(&report)
	}
	*q6.BridgeValidationReportFieldBudget(&report) = nil
	*q6.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "ECIDMeasurementInitiationRequest")
}
func ValidateECIDMeasurementInitiationResponse(v *q8.ECIDMeasurementInitiationResponse, options ...q5.ValidationOption) (q6.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q6.ValidationReport{}, q5.OperationError(err, "ECIDMeasurementInitiationResponse")
	}
	report, err := BridgeValidateECIDMeasurementInitiationResponseBudget(v, budget)
	if err == nil && !q20.BridgeValidationHasValueMismatch(report) {
		_, err = q8.BridgeECIDMeasurementInitiationResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		err = *q6.BridgeValidationReportFieldErr(&report)
	}
	*q6.BridgeValidationReportFieldBudget(&report) = nil
	*q6.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "ECIDMeasurementInitiationResponse")
}
func ValidateOTDOAInformationResponse(v *q9.OTDOAInformationResponse, options ...q5.ValidationOption) (q6.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q6.ValidationReport{}, q5.OperationError(err, "OTDOAInformationResponse")
	}
	report, err := BridgeValidateOTDOAInformationResponseBudget(v, budget)
	if err == nil && !q20.BridgeValidationHasValueMismatch(report) {
		_, err = q9.BridgeOTDOAInformationResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		err = *q6.BridgeValidationReportFieldErr(&report)
	}
	*q6.BridgeValidationReportFieldBudget(&report) = nil
	*q6.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "OTDOAInformationResponse")
}
func ValidateUTDOAInformationRequest(v *q10.UTDOAInformationRequest, options ...q5.ValidationOption) (q6.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q6.ValidationReport{}, q5.OperationError(err, "UTDOAInformationRequest")
	}
	report, err := BridgeValidateUTDOAInformationRequestBudget(v, budget)
	if err == nil && !q20.BridgeValidationHasValueMismatch(report) {
		_, err = q10.BridgeUTDOAInformationRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		err = *q6.BridgeValidationReportFieldErr(&report)
	}
	*q6.BridgeValidationReportFieldBudget(&report) = nil
	*q6.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "UTDOAInformationRequest")
}
func ValidateUTDOAInformationResponse(v *q12.UTDOAInformationResponse, options ...q5.ValidationOption) (q6.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q6.ValidationReport{}, q5.OperationError(err, "UTDOAInformationResponse")
	}
	report, err := BridgeValidateUTDOAInformationResponseBudget(v, budget)
	if err == nil && !q20.BridgeValidationHasValueMismatch(report) {
		_, err = q12.BridgeUTDOAInformationResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		err = *q6.BridgeValidationReportFieldErr(&report)
	}
	*q6.BridgeValidationReportFieldBudget(&report) = nil
	*q6.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "UTDOAInformationResponse")
}
func ValidateUTDOAInformationFailure(v *q10.UTDOAInformationFailure, options ...q5.ValidationOption) (q6.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q6.ValidationReport{}, q5.OperationError(err, "UTDOAInformationFailure")
	}
	report, err := BridgeValidateUTDOAInformationFailureBudget(v, budget)
	if err == nil && !q20.BridgeValidationHasValueMismatch(report) {
		_, err = q10.BridgeUTDOAInformationFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		err = *q6.BridgeValidationReportFieldErr(&report)
	}
	*q6.BridgeValidationReportFieldBudget(&report) = nil
	*q6.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "UTDOAInformationFailure")
}
func ValidateUTDOAInformationUpdate(v *q12.UTDOAInformationUpdate, options ...q5.ValidationOption) (q6.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q6.ValidationReport{}, q5.OperationError(err, "UTDOAInformationUpdate")
	}
	report, err := BridgeValidateUTDOAInformationUpdateBudget(v, budget)
	if err == nil && !q20.BridgeValidationHasValueMismatch(report) {
		_, err = q12.BridgeUTDOAInformationUpdateMethodMarshalAPERBudget(v, budget, false)
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		err = *q6.BridgeValidationReportFieldErr(&report)
	}
	*q6.BridgeValidationReportFieldBudget(&report) = nil
	*q6.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "UTDOAInformationUpdate")
}
func ValidateAssistanceInformationControl(v *q15.AssistanceInformationControl, options ...q5.ValidationOption) (q6.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q6.ValidationReport{}, q5.OperationError(err, "AssistanceInformationControl")
	}
	report, err := BridgeValidateAssistanceInformationControlBudget(v, budget)
	if err == nil && !q20.BridgeValidationHasValueMismatch(report) {
		_, err = q15.BridgeAssistanceInformationControlMethodMarshalAPERBudget(v, budget, false)
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		err = *q6.BridgeValidationReportFieldErr(&report)
	}
	*q6.BridgeValidationReportFieldBudget(&report) = nil
	*q6.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "AssistanceInformationControl")
}
func ValidateMessage(v *q17.LPPAPDU, options ...q5.ValidationOption) (q6.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q6.ValidationReport{}, q5.OperationError(err, "Message")
	}
	report, err := BridgeValidateMessageBudget(v, budget)
	if err == nil && !q20.BridgeValidationHasValueMismatch(report) {
		_, err = q17.BridgeLPPAPDUMethodMarshalAPERBudget(v, budget, false)
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		err = *q6.BridgeValidationReportFieldErr(&report)
	}
	*q6.BridgeValidationReportFieldBudget(&report) = nil
	*q6.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "Message")
}
func BridgeWalkValidationAddOTDOACellInformation(v *q15.AddOTDOACellInformation, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q6.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationOTDOACellInformationItem(&(*v)[i], report, q7.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationAddOTDOACells(v *q15.AddOTDOACells, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q6.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationAddOTDOACellsElem(&(*v)[i], report, q7.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationAddOTDOACellsElem(v *q15.AddOTDOACellsElem, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationAddOTDOACellInformation(&v.AddOTDOACellInfo, report, path+".add-OTDOACellInfo", false)
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q16.FieldInfo{}
				q13.BridgeMergeNestedValidation(report, q6.BridgeAddOTDOACellsExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q6.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationAssistanceInformation(v *q14.AssistanceInformation, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationSystemInformation(&v.SystemInformation, report, path+".systemInformation", false)
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q16.FieldInfo{}
				q13.BridgeMergeNestedValidation(report, q6.BridgeAssistanceInformationExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q6.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationAssistanceInformationControl(v *q15.AssistanceInformationControl, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q16.FieldInfo{q14.AssistanceInformationControlIEs().AssistanceInformation().Info(), q14.AssistanceInformationControlIEs().Broadcast().Info()}
			q13.BridgeMergeNestedValidation(report, q15.BridgeAssistanceInformationControlIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q6.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q16.ProtocolIEID(22):
				if value, ok := fields[i].Value.AsAssistanceInformation(); ok {
					BridgeWalkValidationAssistanceInformation(value, report, q7.Sprintf("%s[%d]{id=22}", nestedPath, i), false)
				}
			}
		}
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECIDMeasurementInitiationRequest(v *q4.ECIDMeasurementInitiationRequest, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q16.FieldInfo{q4.ECIDMeasurementInitiationRequestIEs().ESMLCUEMeasurementID().Info(), q4.ECIDMeasurementInitiationRequestIEs().ReportCharacteristics().Info(), q4.ECIDMeasurementInitiationRequestIEs().MeasurementPeriodicity().Info(), q4.ECIDMeasurementInitiationRequestIEs().MeasurementQuantities().Info(), q4.ECIDMeasurementInitiationRequestIEs().InterRATMeasurementQuantities().Info(), q4.ECIDMeasurementInitiationRequestIEs().WLANMeasurementQuantities().Info()}
			q13.BridgeMergeNestedValidation(report, q4.BridgeECIDMeasurementInitiationRequestIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q6.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q16.ProtocolIEID(5):
				if value, ok := fields[i].Value.AsMeasurementQuantities(); ok {
					q17.BridgeWalkValidationMeasurementQuantities(value, report, q7.Sprintf("%s[%d]{id=5}", nestedPath, i), false)
				}
			case q16.ProtocolIEID(15):
				if value, ok := fields[i].Value.AsInterRATMeasurementQuantities(); ok {
					q17.BridgeWalkValidationInterRATMeasurementQuantities(value, report, q7.Sprintf("%s[%d]{id=15}", nestedPath, i), false)
				}
			case q16.ProtocolIEID(19):
				if value, ok := fields[i].Value.AsWLANMeasurementQuantities(); ok {
					BridgeWalkValidationWLANMeasurementQuantities(value, report, q7.Sprintf("%s[%d]{id=19}", nestedPath, i), false)
				}
			}
		}
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECIDMeasurementInitiationResponse(v *q8.ECIDMeasurementInitiationResponse, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q16.FieldInfo{q8.ECIDMeasurementInitiationResponseIEs().ESMLCUEMeasurementID().Info(), q8.ECIDMeasurementInitiationResponseIEs().ENBUEMeasurementID().Info(), q8.ECIDMeasurementInitiationResponseIEs().ECIDMeasurementResult().Info(), q8.ECIDMeasurementInitiationResponseIEs().CriticalityDiagnostics().Info(), q8.ECIDMeasurementInitiationResponseIEs().CellPortionID().Info(), q8.ECIDMeasurementInitiationResponseIEs().InterRATMeasurementResult().Info(), q8.ECIDMeasurementInitiationResponseIEs().WLANMeasurementResult().Info()}
			q13.BridgeMergeNestedValidation(report, q17.BridgeECIDMeasurementInitiationResponseIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q6.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q16.ProtocolIEID(7):
				if value, ok := fields[i].Value.AsECIDMeasurementResult(); ok {
					q17.BridgeWalkValidationECIDMeasurementResult(value, report, q7.Sprintf("%s[%d]{id=7}", nestedPath, i), false)
				}
			case q16.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					q17.BridgeWalkValidationCriticalityDiagnostics(value, report, q7.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			case q16.ProtocolIEID(17):
				if value, ok := fields[i].Value.AsInterRATMeasurementResult(); ok {
					q17.BridgeWalkValidationInterRATMeasurementResult(value, report, q7.Sprintf("%s[%d]{id=17}", nestedPath, i), false)
				}
			case q16.ProtocolIEID(21):
				if value, ok := fields[i].Value.AsWLANMeasurementResult(); ok {
					BridgeWalkValidationWLANMeasurementResult(value, report, q7.Sprintf("%s[%d]{id=21}", nestedPath, i), false)
				}
			}
		}
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLPPAPDU(v *q17.LPPAPDU, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == q16.LPPAPDUChoiceInitiatingMessage {
		if v.InitiatingMessage != nil {
			q17.BridgeWalkValidationInitiatingMessage(v.InitiatingMessage, report, path+".initiatingMessage", false)
		}
	}
	if v.Choice == q16.LPPAPDUChoiceSuccessfulOutcome {
		if v.SuccessfulOutcome != nil {
			BridgeWalkValidationSuccessfulOutcome(v.SuccessfulOutcome, report, path+".successfulOutcome", false)
		}
	}
	if v.Choice == q16.LPPAPDUChoiceUnsuccessfulOutcome {
		if v.UnsuccessfulOutcome != nil {
			BridgeWalkValidationUnsuccessfulOutcome(v.UnsuccessfulOutcome, report, path+".unsuccessfulOutcome", false)
		}
	}
}
func BridgeWalkValidationMBSFNsubframeConfiguration(v *q6.MBSFNsubframeConfiguration, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q6.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationMBSFNsubframeConfigurationValue(&(*v)[i], report, q7.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationMBSFNsubframeConfigurationValue(v *q6.MBSFNsubframeConfigurationValue, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationSubframeallocation(&v.SubframeAllocation, report, path+".subframeAllocation", false)
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationOTDOACellInformation(v *q15.OTDOACellInformation, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q6.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationOTDOACellInformationItem(&(*v)[i], report, q7.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationOTDOACellInformationItem(v *q15.OTDOACellInformationItem, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == q16.OTDOACellInformationItemChoiceCellId {
		if v.CellId != nil {
			q17.BridgeWalkValidationECGI(v.CellId, report, path+".cellId", false)
		}
	}
	if v.Choice == q16.OTDOACellInformationItemChoiceEUTRANAccessPointPosition {
		if v.EUTRANAccessPointPosition != nil {
			q17.BridgeWalkValidationEUTRANAccessPointPosition(v.EUTRANAccessPointPosition, report, path+".e-UTRANAccessPointPosition", false)
		}
	}
	if v.Choice == q16.OTDOACellInformationItemChoicePRSMutingConfiguration {
		if v.PRSMutingConfiguration != nil {
			q17.BridgeWalkValidationPRSMutingConfiguration(v.PRSMutingConfiguration, report, path+".pRSMutingConfiguration", false)
		}
	}
	if v.Choice == q16.OTDOACellInformationItemChoiceMBSFNsubframeConfiguration {
		if v.MBSFNsubframeConfiguration != nil {
			BridgeWalkValidationMBSFNsubframeConfiguration(&v.MBSFNsubframeConfiguration, report, path+".mBSFNsubframeConfiguration", false)
		}
	}
	if v.Choice == q16.OTDOACellInformationItemChoiceNPRSConfiguration {
		if v.NPRSConfiguration != nil {
			q17.BridgeWalkValidationNPRSConfiguration(v.NPRSConfiguration, report, path+".nPRSConfiguration", false)
		}
	}
	if v.Choice == q16.OTDOACellInformationItemChoicePRSFreqHoppingConfig {
		if v.PRSFreqHoppingConfig != nil {
			q17.BridgeWalkValidationPRSFrequencyHoppingConfiguration(v.PRSFreqHoppingConfig, report, path+".pRSFreqHoppingConfig", false)
		}
	}
	if v.Choice == q16.OTDOACellInformationItemChoiceNPRSType2 {
		if v.NPRSType2 != nil {
			q17.BridgeWalkValidationNPRSConfiguration(v.NPRSType2, report, path+".nPRSType2", false)
		}
	}
	if v.Choice == q16.OTDOACellInformationItemChoiceTddConfiguration {
		if v.TddConfiguration != nil {
			BridgeWalkValidationTDDConfiguration(v.TddConfiguration, report, path+".tddConfiguration", false)
		}
	}
}
func BridgeWalkValidationOTDOACells(v *q10.OTDOACells, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q6.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationOTDOACellsElem(&(*v)[i], report, q7.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationOTDOACellsElem(v *q10.OTDOACellsElem, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationOTDOACellInformation(&v.OTDOACellInfo, report, path+".oTDOACellInfo", false)
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q16.FieldInfo{}
				q13.BridgeMergeNestedValidation(report, q18.BridgeOTDOACellsExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q6.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationOTDOAInformationResponse(v *q9.OTDOAInformationResponse, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q16.FieldInfo{q9.OTDOAInformationResponseIEs().OTDOACells().Info(), q9.OTDOAInformationResponseIEs().CriticalityDiagnostics().Info(), q9.OTDOAInformationResponseIEs().AddOTDOACells().Info()}
			q13.BridgeMergeNestedValidation(report, q9.BridgeOTDOAInformationResponseIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q6.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q16.ProtocolIEID(8):
				if value, ok := fields[i].Value.AsOTDOACells(); ok {
					BridgeWalkValidationOTDOACells(value, report, q7.Sprintf("%s[%d]{id=8}", nestedPath, i), false)
				}
			case q16.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					q17.BridgeWalkValidationCriticalityDiagnostics(value, report, q7.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			case q16.ProtocolIEID(18):
				if value, ok := fields[i].Value.AsAddOTDOACells(); ok {
					BridgeWalkValidationAddOTDOACells(value, report, q7.Sprintf("%s[%d]{id=18}", nestedPath, i), false)
				}
			}
		}
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSubframeallocation(v *q6.Subframeallocation, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationSuccessfulOutcome(v *q8.SuccessfulOutcome, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSystemInformation(v *q14.SystemInformation, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q6.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationSystemInformationElem(&(*v)[i], report, q7.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationSystemInformationElem(v *q14.SystemInformationElem, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	q17.BridgeWalkValidationPosSIBs(&v.PosSIBs, report, path+".posSIBs", false)
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q16.FieldInfo{}
				q13.BridgeMergeNestedValidation(report, q15.BridgeSystemInformationExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q6.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTDDConfiguration(v *q15.TDDConfiguration, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q16.FieldInfo{}
				q13.BridgeMergeNestedValidation(report, q10.BridgeTDDConfigurationExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q6.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationULConfiguration(v *q11.ULConfiguration, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	q17.BridgeWalkValidationSRSConfigurationForAllCells(&v.SrsConfiguration, report, path+".srsConfiguration", false)
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUTDOAInformationFailure(v *q10.UTDOAInformationFailure, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q16.FieldInfo{q11.UTDOAInformationFailureIEs().Cause().Info(), q11.UTDOAInformationFailureIEs().CriticalityDiagnostics().Info()}
			q13.BridgeMergeNestedValidation(report, q10.BridgeUTDOAInformationFailureIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q6.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q16.ProtocolIEID(0):
				if value, ok := fields[i].Value.AsCause(); ok {
					q17.BridgeWalkValidationCause(value, report, q7.Sprintf("%s[%d]{id=0}", nestedPath, i), false)
				}
			case q16.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					q17.BridgeWalkValidationCriticalityDiagnostics(value, report, q7.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			}
		}
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUTDOAInformationRequest(v *q10.UTDOAInformationRequest, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q16.FieldInfo{q6.UTDOAInformationRequestIEs().RequestedSRSTransmissionCharacteristics().Info()}
			q13.BridgeMergeNestedValidation(report, q10.BridgeUTDOAInformationRequestIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q6.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q16.ProtocolIEID(12):
				if value, ok := fields[i].Value.AsRequestedSRSTransmissionCharacteristics(); ok {
					q17.BridgeWalkValidationRequestedSRSTransmissionCharacteristics(value, report, q7.Sprintf("%s[%d]{id=12}", nestedPath, i), false)
				}
			}
		}
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUTDOAInformationResponse(v *q12.UTDOAInformationResponse, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q16.FieldInfo{q11.UTDOAInformationResponseIEs().ULConfiguration().Info(), q11.UTDOAInformationResponseIEs().CriticalityDiagnostics().Info()}
			q13.BridgeMergeNestedValidation(report, q12.BridgeUTDOAInformationResponseIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q6.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q16.ProtocolIEID(13):
				if value, ok := fields[i].Value.AsULConfiguration(); ok {
					BridgeWalkValidationULConfiguration(value, report, q7.Sprintf("%s[%d]{id=13}", nestedPath, i), false)
				}
			case q16.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					q17.BridgeWalkValidationCriticalityDiagnostics(value, report, q7.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			}
		}
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUTDOAInformationUpdate(v *q12.UTDOAInformationUpdate, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q16.FieldInfo{q13.UTDOAInformationUpdateIEs().ULConfiguration().Info()}
			q13.BridgeMergeNestedValidation(report, q12.BridgeUTDOAInformationUpdateIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q6.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q16.ProtocolIEID(13):
				if value, ok := fields[i].Value.AsULConfiguration(); ok {
					BridgeWalkValidationULConfiguration(value, report, q7.Sprintf("%s[%d]{id=13}", nestedPath, i), false)
				}
			}
		}
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUnsuccessfulOutcome(v *q10.UnsuccessfulOutcome, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationWLANChannelList(v *q16.WLANChannelList, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationWLANMeasurementQuantities(v *q20.WLANMeasurementQuantities, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q6.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := q7.Sprintf("%s[%d]", path, i)
		rows := []q16.FieldInfo{q20.WLANMeasurementQuantitiesItemIEs().WLANMeasurementQuantitiesItem().Info()}
		q13.BridgeMergeNestedValidation(report, q4.BridgeWLANMeasurementQuantitiesItemIEValueValidateLPPaIEContainer(q20.WLANMeasurementQuantitiesItemIEContainer{field}, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
		fields := q20.WLANMeasurementQuantitiesItemIEContainer{field}
		for i := range fields {
			if *q6.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q16.ProtocolIEID(20):
				if value, ok := fields[i].Value.AsWLANMeasurementQuantitiesItem(); ok {
					BridgeWalkValidationWLANMeasurementQuantitiesItem(value, report, q7.Sprintf("%s[%d]{id=20}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationWLANMeasurementQuantitiesItem(v *q20.WLANMeasurementQuantitiesItem, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q16.FieldInfo{}
				q13.BridgeMergeNestedValidation(report, q4.BridgeWLANMeasurementQuantitiesValueExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q6.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationWLANMeasurementResult(v *q8.WLANMeasurementResult, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q6.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationWLANMeasurementResultItem(&(*v)[i], report, q7.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationWLANMeasurementResultItem(v *q8.WLANMeasurementResultItem, report *q6.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q6.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q6.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.WLANChannelList != nil {
		BridgeWalkValidationWLANChannelList(&v.WLANChannelList, report, path+".wLANChannelList", false)
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q16.FieldInfo{}
				q13.BridgeMergeNestedValidation(report, q17.BridgeWLANMeasurementResultItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q6.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q6.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q6.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
