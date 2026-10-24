// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s24 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s24

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s14"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s15"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s16"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s17"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s18"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s20"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s22"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s23"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

func NewECIDMeasurementInitiationRequest(fields s21.ECIDMeasurementInitiationRequestIEContainer, options ...aper.BuildOption) (s21.ECIDMeasurementInitiationRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s21.ECIDMeasurementInitiationRequest{}, aper.OperationError(err, "ECIDMeasurementInitiationRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s21.ECIDMeasurementInitiationRequestIEField](bb, uint64(len(fields))); err != nil {
		return s21.ECIDMeasurementInitiationRequest{}, aper.OperationError(err, "ECIDMeasurementInitiationRequest")
	}
	v := s21.ECIDMeasurementInitiationRequest{ProtocolIEs: make(s21.ECIDMeasurementInitiationRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateECIDMeasurementInitiationRequestBudget(&v, budget)
	if err != nil {
		return s21.ECIDMeasurementInitiationRequest{}, aper.OperationError(err, "ECIDMeasurementInitiationRequest")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s21.ECIDMeasurementInitiationRequest{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "ECIDMeasurementInitiationRequest")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s21.ECIDMeasurementInitiationRequest{}, aper.OperationError(&s09.BuildError{Issues: issues}, "ECIDMeasurementInitiationRequest")
	}
	if _, err := s21.BridgeECIDMeasurementInitiationRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s21.ECIDMeasurementInitiationRequest{}, aper.OperationError(fmt.Errorf("%s %w", "ECIDMeasurementInitiationRequest.protocolIEs:", err), "ECIDMeasurementInitiationRequest")
	}
	return v, aper.OperationError(nil, "ECIDMeasurementInitiationRequest")
}
func NewECIDMeasurementInitiationResponse(fields s22.ECIDMeasurementInitiationResponseIEContainer, options ...aper.BuildOption) (s22.ECIDMeasurementInitiationResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.ECIDMeasurementInitiationResponse{}, aper.OperationError(err, "ECIDMeasurementInitiationResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s22.ECIDMeasurementInitiationResponseIEField](bb, uint64(len(fields))); err != nil {
		return s22.ECIDMeasurementInitiationResponse{}, aper.OperationError(err, "ECIDMeasurementInitiationResponse")
	}
	v := s22.ECIDMeasurementInitiationResponse{ProtocolIEs: make(s22.ECIDMeasurementInitiationResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateECIDMeasurementInitiationResponseBudget(&v, budget)
	if err != nil {
		return s22.ECIDMeasurementInitiationResponse{}, aper.OperationError(err, "ECIDMeasurementInitiationResponse")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s22.ECIDMeasurementInitiationResponse{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "ECIDMeasurementInitiationResponse")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s22.ECIDMeasurementInitiationResponse{}, aper.OperationError(&s09.BuildError{Issues: issues}, "ECIDMeasurementInitiationResponse")
	}
	if _, err := s22.BridgeECIDMeasurementInitiationResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s22.ECIDMeasurementInitiationResponse{}, aper.OperationError(fmt.Errorf("%s %w", "ECIDMeasurementInitiationResponse.protocolIEs:", err), "ECIDMeasurementInitiationResponse")
	}
	return v, aper.OperationError(nil, "ECIDMeasurementInitiationResponse")
}
func NewOTDOAInformationResponse(fields s18.OTDOAInformationResponseIEContainer, options ...aper.BuildOption) (s18.OTDOAInformationResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.OTDOAInformationResponse{}, aper.OperationError(err, "OTDOAInformationResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s18.OTDOAInformationResponseIEField](bb, uint64(len(fields))); err != nil {
		return s18.OTDOAInformationResponse{}, aper.OperationError(err, "OTDOAInformationResponse")
	}
	v := s18.OTDOAInformationResponse{ProtocolIEs: make(s18.OTDOAInformationResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateOTDOAInformationResponseBudget(&v, budget)
	if err != nil {
		return s18.OTDOAInformationResponse{}, aper.OperationError(err, "OTDOAInformationResponse")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s18.OTDOAInformationResponse{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "OTDOAInformationResponse")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s18.OTDOAInformationResponse{}, aper.OperationError(&s09.BuildError{Issues: issues}, "OTDOAInformationResponse")
	}
	if _, err := s18.BridgeOTDOAInformationResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s18.OTDOAInformationResponse{}, aper.OperationError(fmt.Errorf("%s %w", "OTDOAInformationResponse.protocolIEs:", err), "OTDOAInformationResponse")
	}
	return v, aper.OperationError(nil, "OTDOAInformationResponse")
}
func NewUTDOAInformationRequest(fields s09.UTDOAInformationRequestIEContainer, options ...aper.BuildOption) (s16.UTDOAInformationRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s16.UTDOAInformationRequest{}, aper.OperationError(err, "UTDOAInformationRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s09.UTDOAInformationRequestIEField](bb, uint64(len(fields))); err != nil {
		return s16.UTDOAInformationRequest{}, aper.OperationError(err, "UTDOAInformationRequest")
	}
	v := s16.UTDOAInformationRequest{ProtocolIEs: make(s09.UTDOAInformationRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUTDOAInformationRequestBudget(&v, budget)
	if err != nil {
		return s16.UTDOAInformationRequest{}, aper.OperationError(err, "UTDOAInformationRequest")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s16.UTDOAInformationRequest{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "UTDOAInformationRequest")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s16.UTDOAInformationRequest{}, aper.OperationError(&s09.BuildError{Issues: issues}, "UTDOAInformationRequest")
	}
	if _, err := s16.BridgeUTDOAInformationRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s16.UTDOAInformationRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UTDOAInformationRequest.protocolIEs:", err), "UTDOAInformationRequest")
	}
	return v, aper.OperationError(nil, "UTDOAInformationRequest")
}
func NewUTDOAInformationResponse(fields s10.UTDOAInformationResponseIEContainer, options ...aper.BuildOption) (s17.UTDOAInformationResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.UTDOAInformationResponse{}, aper.OperationError(err, "UTDOAInformationResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s10.UTDOAInformationResponseIEField](bb, uint64(len(fields))); err != nil {
		return s17.UTDOAInformationResponse{}, aper.OperationError(err, "UTDOAInformationResponse")
	}
	v := s17.UTDOAInformationResponse{ProtocolIEs: make(s10.UTDOAInformationResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUTDOAInformationResponseBudget(&v, budget)
	if err != nil {
		return s17.UTDOAInformationResponse{}, aper.OperationError(err, "UTDOAInformationResponse")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s17.UTDOAInformationResponse{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "UTDOAInformationResponse")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s17.UTDOAInformationResponse{}, aper.OperationError(&s09.BuildError{Issues: issues}, "UTDOAInformationResponse")
	}
	if _, err := s17.BridgeUTDOAInformationResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s17.UTDOAInformationResponse{}, aper.OperationError(fmt.Errorf("%s %w", "UTDOAInformationResponse.protocolIEs:", err), "UTDOAInformationResponse")
	}
	return v, aper.OperationError(nil, "UTDOAInformationResponse")
}
func NewUTDOAInformationFailure(fields s10.UTDOAInformationFailureIEContainer, options ...aper.BuildOption) (s16.UTDOAInformationFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s16.UTDOAInformationFailure{}, aper.OperationError(err, "UTDOAInformationFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s10.UTDOAInformationFailureIEField](bb, uint64(len(fields))); err != nil {
		return s16.UTDOAInformationFailure{}, aper.OperationError(err, "UTDOAInformationFailure")
	}
	v := s16.UTDOAInformationFailure{ProtocolIEs: make(s10.UTDOAInformationFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUTDOAInformationFailureBudget(&v, budget)
	if err != nil {
		return s16.UTDOAInformationFailure{}, aper.OperationError(err, "UTDOAInformationFailure")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s16.UTDOAInformationFailure{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "UTDOAInformationFailure")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s16.UTDOAInformationFailure{}, aper.OperationError(&s09.BuildError{Issues: issues}, "UTDOAInformationFailure")
	}
	if _, err := s16.BridgeUTDOAInformationFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s16.UTDOAInformationFailure{}, aper.OperationError(fmt.Errorf("%s %w", "UTDOAInformationFailure.protocolIEs:", err), "UTDOAInformationFailure")
	}
	return v, aper.OperationError(nil, "UTDOAInformationFailure")
}
func NewUTDOAInformationUpdate(fields s11.UTDOAInformationUpdateIEContainer, options ...aper.BuildOption) (s17.UTDOAInformationUpdate, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.UTDOAInformationUpdate{}, aper.OperationError(err, "UTDOAInformationUpdate")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.UTDOAInformationUpdateIEField](bb, uint64(len(fields))); err != nil {
		return s17.UTDOAInformationUpdate{}, aper.OperationError(err, "UTDOAInformationUpdate")
	}
	v := s17.UTDOAInformationUpdate{ProtocolIEs: make(s11.UTDOAInformationUpdateIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUTDOAInformationUpdateBudget(&v, budget)
	if err != nil {
		return s17.UTDOAInformationUpdate{}, aper.OperationError(err, "UTDOAInformationUpdate")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s17.UTDOAInformationUpdate{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "UTDOAInformationUpdate")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s17.UTDOAInformationUpdate{}, aper.OperationError(&s09.BuildError{Issues: issues}, "UTDOAInformationUpdate")
	}
	if _, err := s17.BridgeUTDOAInformationUpdateMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s17.UTDOAInformationUpdate{}, aper.OperationError(fmt.Errorf("%s %w", "UTDOAInformationUpdate.protocolIEs:", err), "UTDOAInformationUpdate")
	}
	return v, aper.OperationError(nil, "UTDOAInformationUpdate")
}
func NewAssistanceInformationControl(fields s14.AssistanceInformationControlIEContainer, options ...aper.BuildOption) (s15.AssistanceInformationControl, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s15.AssistanceInformationControl{}, aper.OperationError(err, "AssistanceInformationControl")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s14.AssistanceInformationControlIEField](bb, uint64(len(fields))); err != nil {
		return s15.AssistanceInformationControl{}, aper.OperationError(err, "AssistanceInformationControl")
	}
	v := s15.AssistanceInformationControl{ProtocolIEs: make(s14.AssistanceInformationControlIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateAssistanceInformationControlBudget(&v, budget)
	if err != nil {
		return s15.AssistanceInformationControl{}, aper.OperationError(err, "AssistanceInformationControl")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s15.AssistanceInformationControl{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "AssistanceInformationControl")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s15.AssistanceInformationControl{}, aper.OperationError(&s09.BuildError{Issues: issues}, "AssistanceInformationControl")
	}
	if _, err := s15.BridgeAssistanceInformationControlMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s15.AssistanceInformationControl{}, aper.OperationError(fmt.Errorf("%s %w", "AssistanceInformationControl.protocolIEs:", err), "AssistanceInformationControl")
	}
	return v, aper.OperationError(nil, "AssistanceInformationControl")
}

// Initiating returns the binding for this procedure's initiating message.
func (ECIDMeasurementInitiationDescriptor) Initiating() s21.ECIDMeasurementInitiationRequestInitiatingBinding {
	return func() s21.ECIDMeasurementInitiationRequestInitiatingBinding {
		sealed := s21.ECIDMeasurementInitiationRequestInitiatingBinding{}
		*s21.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldInfo(&sealed) = ECIDMeasurementInitiationProcedure().Info()
		*s21.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldValidate(&sealed) = func(v *s21.ECIDMeasurementInitiationRequest, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return BridgeValidateECIDMeasurementInitiationRequestBudget(v, budget)
		}
		*s21.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldEncode(&sealed) = func(v *s21.ECIDMeasurementInitiationRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s21.BridgeECIDMeasurementInitiationRequestMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s21.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.ECIDMeasurementInitiationRequest, error) {
			var v s21.ECIDMeasurementInitiationRequest
			err := s21.BridgeECIDMeasurementInitiationRequestMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s21.ECIDMeasurementInitiationRequest{}, err
			}
			*s21.BridgeECIDMeasurementInitiationRequestFieldReceived(&v) = true
			*s21.BridgeECIDMeasurementInitiationRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s21.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldInject(&sealed) = func(v s21.ECIDMeasurementInitiationRequest) s21.InitiatingValue {
			return func() s21.InitiatingValue {
				sealed := s21.InitiatingValue{}
				*s21.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(2)
				*s21.BridgeInitiatingValueFieldBodyECIDMeasurementInitiationRequest(&sealed) = &v
				return sealed
			}()
		}
		*s21.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldCapture(&sealed) = func(v s21.ECIDMeasurementInitiationRequest, options aper.DecodeState) (s21.ECIDMeasurementInitiationRequest, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s21.BridgeCaptureLPPaECIDMeasurementInitiationRequest(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldCompare(&sealed) = func(v s21.ECIDMeasurementInitiationRequest, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s21.BridgeCompareLPPaECIDMeasurementInitiationRequest(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s21.BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementInitiationRequest"
			return sealed
		}()
		return sealed
	}()

}

// Successful returns the binding for this procedure's successful outcome.
func (ECIDMeasurementInitiationDescriptor) Successful() s23.ECIDMeasurementInitiationResponseSuccessfulBinding {
	return func() s23.ECIDMeasurementInitiationResponseSuccessfulBinding {
		sealed := s23.ECIDMeasurementInitiationResponseSuccessfulBinding{}
		*s23.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldInfo(&sealed) = ECIDMeasurementInitiationProcedure().Info()
		*s23.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s22.ECIDMeasurementInitiationResponse, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return BridgeValidateECIDMeasurementInitiationResponseBudget(v, budget)
		}
		*s23.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s22.ECIDMeasurementInitiationResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s22.BridgeECIDMeasurementInitiationResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s23.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s22.ECIDMeasurementInitiationResponse, error) {
			var v s22.ECIDMeasurementInitiationResponse
			err := s22.BridgeECIDMeasurementInitiationResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s22.ECIDMeasurementInitiationResponse{}, err
			}
			*s22.BridgeECIDMeasurementInitiationResponseFieldReceived(&v) = true
			*s22.BridgeECIDMeasurementInitiationResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s23.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldInject(&sealed) = func(v s22.ECIDMeasurementInitiationResponse) s22.SuccessfulValue {
			return func() s22.SuccessfulValue {
				sealed := s22.SuccessfulValue{}
				*s22.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(2)
				*s22.BridgeSuccessfulValueFieldBodyECIDMeasurementInitiationResponse(&sealed) = &v
				return sealed
			}()
		}
		*s23.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldCapture(&sealed) = func(v s22.ECIDMeasurementInitiationResponse, options aper.DecodeState) (s22.ECIDMeasurementInitiationResponse, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s22.BridgeCaptureLPPaECIDMeasurementInitiationResponse(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldCompare(&sealed) = func(v s22.ECIDMeasurementInitiationResponse, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s22.BridgeCompareLPPaECIDMeasurementInitiationResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s23.BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementInitiationResponse"
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the binding for this procedure's unsuccessful outcome.
func (ECIDMeasurementInitiationDescriptor) Unsuccessful() s16.ECIDMeasurementInitiationFailureUnsuccessfulBinding {
	return func() s16.ECIDMeasurementInitiationFailureUnsuccessfulBinding {
		sealed := s16.ECIDMeasurementInitiationFailureUnsuccessfulBinding{}
		*s16.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldInfo(&sealed) = ECIDMeasurementInitiationProcedure().Info()
		*s16.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s11.ECIDMeasurementInitiationFailure, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return s23.BridgeValidateECIDMeasurementInitiationFailureBudget(v, budget)
		}
		*s16.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s11.ECIDMeasurementInitiationFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s11.BridgeECIDMeasurementInitiationFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s16.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.ECIDMeasurementInitiationFailure, error) {
			var v s11.ECIDMeasurementInitiationFailure
			err := s11.BridgeECIDMeasurementInitiationFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s11.ECIDMeasurementInitiationFailure{}, err
			}
			*s11.BridgeECIDMeasurementInitiationFailureFieldReceived(&v) = true
			*s11.BridgeECIDMeasurementInitiationFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s16.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s11.ECIDMeasurementInitiationFailure) s16.UnsuccessfulValue {
			return func() s16.UnsuccessfulValue {
				sealed := s16.UnsuccessfulValue{}
				*s16.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(2)
				*s16.BridgeUnsuccessfulValueFieldBodyECIDMeasurementInitiationFailure(&sealed) = &v
				return sealed
			}()
		}
		*s16.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s11.ECIDMeasurementInitiationFailure, options aper.DecodeState) (s11.ECIDMeasurementInitiationFailure, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s11.BridgeCaptureLPPaECIDMeasurementInitiationFailure(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s16.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s11.ECIDMeasurementInitiationFailure, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s11.BridgeCompareLPPaECIDMeasurementInitiationFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s16.BridgeECIDMeasurementInitiationFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementInitiationFailure"
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the binding for this procedure's initiating message.
func (OTDOAInformationExchangeDescriptor) Initiating() s21.OTDOAInformationRequestInitiatingBinding {
	return func() s21.OTDOAInformationRequestInitiatingBinding {
		sealed := s21.OTDOAInformationRequestInitiatingBinding{}
		*s21.BridgeOTDOAInformationRequestInitiatingBindingFieldInfo(&sealed) = OTDOAInformationExchangeProcedure().Info()
		*s21.BridgeOTDOAInformationRequestInitiatingBindingFieldValidate(&sealed) = func(v *s18.OTDOAInformationRequest, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return s23.BridgeValidateOTDOAInformationRequestBudget(v, budget)
		}
		*s21.BridgeOTDOAInformationRequestInitiatingBindingFieldEncode(&sealed) = func(v *s18.OTDOAInformationRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s18.BridgeOTDOAInformationRequestMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s21.BridgeOTDOAInformationRequestInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.OTDOAInformationRequest, error) {
			var v s18.OTDOAInformationRequest
			err := s18.BridgeOTDOAInformationRequestMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s18.OTDOAInformationRequest{}, err
			}
			*s18.BridgeOTDOAInformationRequestFieldReceived(&v) = true
			*s18.BridgeOTDOAInformationRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s21.BridgeOTDOAInformationRequestInitiatingBindingFieldInject(&sealed) = func(v s18.OTDOAInformationRequest) s21.InitiatingValue {
			return func() s21.InitiatingValue {
				sealed := s21.InitiatingValue{}
				*s21.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(6)
				*s21.BridgeInitiatingValueFieldBodyOTDOAInformationRequest(&sealed) = &v
				return sealed
			}()
		}
		*s21.BridgeOTDOAInformationRequestInitiatingBindingFieldCapture(&sealed) = func(v s18.OTDOAInformationRequest, options aper.DecodeState) (s18.OTDOAInformationRequest, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s18.BridgeCaptureLPPaOTDOAInformationRequest(
				&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*s21.BridgeOTDOAInformationRequestInitiatingBindingFieldCompare(&sealed) = func(v s18.OTDOAInformationRequest, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s18.BridgeCompareLPPaOTDOAInformationRequest(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s21.BridgeOTDOAInformationRequestInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOAInformationRequest"
			return sealed
		}()
		return sealed
	}()

}

// Successful returns the binding for this procedure's successful outcome.
func (OTDOAInformationExchangeDescriptor) Successful() s23.OTDOAInformationResponseSuccessfulBinding {
	return func() s23.OTDOAInformationResponseSuccessfulBinding {
		sealed := s23.OTDOAInformationResponseSuccessfulBinding{}
		*s23.BridgeOTDOAInformationResponseSuccessfulBindingFieldInfo(&sealed) = OTDOAInformationExchangeProcedure().Info()
		*s23.BridgeOTDOAInformationResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s18.OTDOAInformationResponse, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return BridgeValidateOTDOAInformationResponseBudget(v, budget)
		}
		*s23.BridgeOTDOAInformationResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s18.OTDOAInformationResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s18.BridgeOTDOAInformationResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s23.BridgeOTDOAInformationResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.OTDOAInformationResponse, error) {
			var v s18.OTDOAInformationResponse
			err := s18.BridgeOTDOAInformationResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s18.OTDOAInformationResponse{}, err
			}
			*s18.BridgeOTDOAInformationResponseFieldReceived(&v) = true
			*s18.BridgeOTDOAInformationResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s23.BridgeOTDOAInformationResponseSuccessfulBindingFieldInject(&sealed) = func(v s18.OTDOAInformationResponse) s22.SuccessfulValue {
			return func() s22.SuccessfulValue {
				sealed := s22.SuccessfulValue{}
				*s22.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(6)
				*s22.BridgeSuccessfulValueFieldBodyOTDOAInformationResponse(&sealed) = &v
				return sealed
			}()
		}
		*s23.BridgeOTDOAInformationResponseSuccessfulBindingFieldCapture(&sealed) = func(v s18.OTDOAInformationResponse, options aper.DecodeState) (s18.OTDOAInformationResponse, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s18.BridgeCaptureLPPaOTDOAInformationResponse(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeOTDOAInformationResponseSuccessfulBindingFieldCompare(&sealed) = func(v s18.OTDOAInformationResponse, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s18.BridgeCompareLPPaOTDOAInformationResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s23.BridgeOTDOAInformationResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOAInformationResponse"
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the binding for this procedure's unsuccessful outcome.
func (OTDOAInformationExchangeDescriptor) Unsuccessful() s16.OTDOAInformationFailureUnsuccessfulBinding {
	return func() s16.OTDOAInformationFailureUnsuccessfulBinding {
		sealed := s16.OTDOAInformationFailureUnsuccessfulBinding{}
		*s16.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldInfo(&sealed) = OTDOAInformationExchangeProcedure().Info()
		*s16.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s12.OTDOAInformationFailure, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return s23.BridgeValidateOTDOAInformationFailureBudget(v, budget)
		}
		*s16.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s12.OTDOAInformationFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s12.BridgeOTDOAInformationFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s16.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.OTDOAInformationFailure, error) {
			var v s12.OTDOAInformationFailure
			err := s12.BridgeOTDOAInformationFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s12.OTDOAInformationFailure{}, err
			}
			*s12.BridgeOTDOAInformationFailureFieldReceived(&v) = true
			*s12.BridgeOTDOAInformationFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s16.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s12.OTDOAInformationFailure) s16.UnsuccessfulValue {
			return func() s16.UnsuccessfulValue {
				sealed := s16.UnsuccessfulValue{}
				*s16.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(6)
				*s16.BridgeUnsuccessfulValueFieldBodyOTDOAInformationFailure(&sealed) = &v
				return sealed
			}()
		}
		*s16.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s12.OTDOAInformationFailure, options aper.DecodeState) (s12.OTDOAInformationFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s12.BridgeCaptureLPPaOTDOAInformationFailure(
				&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*s16.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s12.OTDOAInformationFailure, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s12.BridgeCompareLPPaOTDOAInformationFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s16.BridgeOTDOAInformationFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOAInformationFailure"
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the binding for this procedure's initiating message.
func (UTDOAInformationExchangeDescriptor) Initiating() s21.UTDOAInformationRequestInitiatingBinding {
	return func() s21.UTDOAInformationRequestInitiatingBinding {
		sealed := s21.UTDOAInformationRequestInitiatingBinding{}
		*s21.BridgeUTDOAInformationRequestInitiatingBindingFieldInfo(&sealed) = UTDOAInformationExchangeProcedure().Info()
		*s21.BridgeUTDOAInformationRequestInitiatingBindingFieldValidate(&sealed) = func(v *s16.UTDOAInformationRequest, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return BridgeValidateUTDOAInformationRequestBudget(v, budget)
		}
		*s21.BridgeUTDOAInformationRequestInitiatingBindingFieldEncode(&sealed) = func(v *s16.UTDOAInformationRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s16.BridgeUTDOAInformationRequestMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s21.BridgeUTDOAInformationRequestInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.UTDOAInformationRequest, error) {
			var v s16.UTDOAInformationRequest
			err := s16.BridgeUTDOAInformationRequestMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s16.UTDOAInformationRequest{}, err
			}
			*s16.BridgeUTDOAInformationRequestFieldReceived(&v) = true
			*s16.BridgeUTDOAInformationRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s21.BridgeUTDOAInformationRequestInitiatingBindingFieldInject(&sealed) = func(v s16.UTDOAInformationRequest) s21.InitiatingValue {
			return func() s21.InitiatingValue {
				sealed := s21.InitiatingValue{}
				*s21.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(7)
				*s21.BridgeInitiatingValueFieldBodyUTDOAInformationRequest(&sealed) = &v
				return sealed
			}()
		}
		*s21.BridgeUTDOAInformationRequestInitiatingBindingFieldCapture(&sealed) = func(v s16.UTDOAInformationRequest, options aper.DecodeState) (s16.UTDOAInformationRequest, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s16.BridgeCaptureLPPaUTDOAInformationRequest(
				&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*s21.BridgeUTDOAInformationRequestInitiatingBindingFieldCompare(&sealed) = func(v s16.UTDOAInformationRequest, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s16.BridgeCompareLPPaUTDOAInformationRequest(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s21.BridgeUTDOAInformationRequestInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UTDOAInformationRequest"
			return sealed
		}()
		return sealed
	}()

}

// Successful returns the binding for this procedure's successful outcome.
func (UTDOAInformationExchangeDescriptor) Successful() s23.UTDOAInformationResponseSuccessfulBinding {
	return func() s23.UTDOAInformationResponseSuccessfulBinding {
		sealed := s23.UTDOAInformationResponseSuccessfulBinding{}
		*s23.BridgeUTDOAInformationResponseSuccessfulBindingFieldInfo(&sealed) = UTDOAInformationExchangeProcedure().Info()
		*s23.BridgeUTDOAInformationResponseSuccessfulBindingFieldValidate(&sealed) = func(v *s17.UTDOAInformationResponse, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return BridgeValidateUTDOAInformationResponseBudget(v, budget)
		}
		*s23.BridgeUTDOAInformationResponseSuccessfulBindingFieldEncode(&sealed) = func(v *s17.UTDOAInformationResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s17.BridgeUTDOAInformationResponseMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s23.BridgeUTDOAInformationResponseSuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.UTDOAInformationResponse, error) {
			var v s17.UTDOAInformationResponse
			err := s17.BridgeUTDOAInformationResponseMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s17.UTDOAInformationResponse{}, err
			}
			*s17.BridgeUTDOAInformationResponseFieldReceived(&v) = true
			*s17.BridgeUTDOAInformationResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s23.BridgeUTDOAInformationResponseSuccessfulBindingFieldInject(&sealed) = func(v s17.UTDOAInformationResponse) s22.SuccessfulValue {
			return func() s22.SuccessfulValue {
				sealed := s22.SuccessfulValue{}
				*s22.BridgeSuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(7)
				*s22.BridgeSuccessfulValueFieldBodyUTDOAInformationResponse(&sealed) = &v
				return sealed
			}()
		}
		*s23.BridgeUTDOAInformationResponseSuccessfulBindingFieldCapture(&sealed) = func(v s17.UTDOAInformationResponse, options aper.DecodeState) (s17.UTDOAInformationResponse, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s17.BridgeCaptureLPPaUTDOAInformationResponse(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUTDOAInformationResponseSuccessfulBindingFieldCompare(&sealed) = func(v s17.UTDOAInformationResponse, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s17.BridgeCompareLPPaUTDOAInformationResponse(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s23.BridgeUTDOAInformationResponseSuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UTDOAInformationResponse"
			return sealed
		}()
		return sealed
	}()

}

// Unsuccessful returns the binding for this procedure's unsuccessful outcome.
func (UTDOAInformationExchangeDescriptor) Unsuccessful() s16.UTDOAInformationFailureUnsuccessfulBinding {
	return func() s16.UTDOAInformationFailureUnsuccessfulBinding {
		sealed := s16.UTDOAInformationFailureUnsuccessfulBinding{}
		*s16.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldInfo(&sealed) = UTDOAInformationExchangeProcedure().Info()
		*s16.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldValidate(&sealed) = func(v *s16.UTDOAInformationFailure, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return BridgeValidateUTDOAInformationFailureBudget(v, budget)
		}
		*s16.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldEncode(&sealed) = func(v *s16.UTDOAInformationFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s16.BridgeUTDOAInformationFailureMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s16.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s16.UTDOAInformationFailure, error) {
			var v s16.UTDOAInformationFailure
			err := s16.BridgeUTDOAInformationFailureMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s16.UTDOAInformationFailure{}, err
			}
			*s16.BridgeUTDOAInformationFailureFieldReceived(&v) = true
			*s16.BridgeUTDOAInformationFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s16.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldInject(&sealed) = func(v s16.UTDOAInformationFailure) s16.UnsuccessfulValue {
			return func() s16.UnsuccessfulValue {
				sealed := s16.UnsuccessfulValue{}
				*s16.BridgeUnsuccessfulValueFieldCode(&sealed) = s00.ProcedureCode(7)
				*s16.BridgeUnsuccessfulValueFieldBodyUTDOAInformationFailure(&sealed) = &v
				return sealed
			}()
		}
		*s16.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldCapture(&sealed) = func(v s16.UTDOAInformationFailure, options aper.DecodeState) (s16.UTDOAInformationFailure, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s16.BridgeCaptureLPPaUTDOAInformationFailure(
				&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*s16.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldCompare(&sealed) = func(v s16.UTDOAInformationFailure, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s16.BridgeCompareLPPaUTDOAInformationFailure(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s16.BridgeUTDOAInformationFailureUnsuccessfulBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UTDOAInformationFailure"
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the binding for this procedure's initiating message.
func (UTDOAInformationUpdateDescriptor) Initiating() s21.UTDOAInformationUpdateInitiatingBinding {
	return func() s21.UTDOAInformationUpdateInitiatingBinding {
		sealed := s21.UTDOAInformationUpdateInitiatingBinding{}
		*s21.BridgeUTDOAInformationUpdateInitiatingBindingFieldInfo(&sealed) = UTDOAInformationUpdateProcedure().Info()
		*s21.BridgeUTDOAInformationUpdateInitiatingBindingFieldValidate(&sealed) = func(v *s17.UTDOAInformationUpdate, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return BridgeValidateUTDOAInformationUpdateBudget(v, budget)
		}
		*s21.BridgeUTDOAInformationUpdateInitiatingBindingFieldEncode(&sealed) = func(v *s17.UTDOAInformationUpdate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s17.BridgeUTDOAInformationUpdateMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s21.BridgeUTDOAInformationUpdateInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.UTDOAInformationUpdate, error) {
			var v s17.UTDOAInformationUpdate
			err := s17.BridgeUTDOAInformationUpdateMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s17.UTDOAInformationUpdate{}, err
			}
			*s17.BridgeUTDOAInformationUpdateFieldReceived(&v) = true
			*s17.BridgeUTDOAInformationUpdateFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s21.BridgeUTDOAInformationUpdateInitiatingBindingFieldInject(&sealed) = func(v s17.UTDOAInformationUpdate) s21.InitiatingValue {
			return func() s21.InitiatingValue {
				sealed := s21.InitiatingValue{}
				*s21.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(8)
				*s21.BridgeInitiatingValueFieldBodyUTDOAInformationUpdate(&sealed) = &v
				return sealed
			}()
		}
		*s21.BridgeUTDOAInformationUpdateInitiatingBindingFieldCapture(&sealed) = func(v s17.UTDOAInformationUpdate, options aper.DecodeState) (s17.UTDOAInformationUpdate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s17.BridgeCaptureLPPaUTDOAInformationUpdate(
				&v,

				&s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeUTDOAInformationUpdateInitiatingBindingFieldCompare(&sealed) = func(v s17.UTDOAInformationUpdate, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s17.BridgeCompareLPPaUTDOAInformationUpdate(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s21.BridgeUTDOAInformationUpdateInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UTDOAInformationUpdate"
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the binding for this procedure's initiating message.
func (AssistanceInformationControlDescriptor) Initiating() s21.AssistanceInformationControlInitiatingBinding {
	return func() s21.AssistanceInformationControlInitiatingBinding {
		sealed := s21.AssistanceInformationControlInitiatingBinding{}
		*s21.BridgeAssistanceInformationControlInitiatingBindingFieldInfo(&sealed) = AssistanceInformationControlProcedure().Info()
		*s21.BridgeAssistanceInformationControlInitiatingBindingFieldValidate(&sealed) = func(v *s15.AssistanceInformationControl, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return BridgeValidateAssistanceInformationControlBudget(v, budget)
		}
		*s21.BridgeAssistanceInformationControlInitiatingBindingFieldEncode(&sealed) = func(v *s15.AssistanceInformationControl, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s15.BridgeAssistanceInformationControlMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s21.BridgeAssistanceInformationControlInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.AssistanceInformationControl, error) {
			var v s15.AssistanceInformationControl
			err := s15.BridgeAssistanceInformationControlMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s15.AssistanceInformationControl{}, err
			}
			*s15.BridgeAssistanceInformationControlFieldReceived(&v) = true
			*s15.BridgeAssistanceInformationControlFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s21.BridgeAssistanceInformationControlInitiatingBindingFieldInject(&sealed) = func(v s15.AssistanceInformationControl) s21.InitiatingValue {
			return func() s21.InitiatingValue {
				sealed := s21.InitiatingValue{}
				*s21.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(9)
				*s21.BridgeInitiatingValueFieldBodyAssistanceInformationControl(&sealed) = &v
				return sealed
			}()
		}
		*s21.BridgeAssistanceInformationControlInitiatingBindingFieldCapture(&sealed) = func(v s15.AssistanceInformationControl, options aper.DecodeState) (s15.AssistanceInformationControl, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s15.BridgeCaptureLPPaAssistanceInformationControl(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeAssistanceInformationControlInitiatingBindingFieldCompare(&sealed) = func(v s15.AssistanceInformationControl, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s15.BridgeCompareLPPaAssistanceInformationControl(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}
		*s21.BridgeAssistanceInformationControlInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceInformationControl"
			return sealed
		}()
		return sealed
	}()

}

// NewLPPAPDUInitiatingMessage constructs and validates a complete LPPa message.
func NewLPPAPDUInitiatingMessage(v s21.InitiatingMessage, options ...aper.BuildOption) (s23.LPPAPDU, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s23.LPPAPDU{}, aper.OperationError(err, "LPPAPDUInitiatingMessage")
	}
	value := s23.BridgeNewLPPAPDUInitiatingMessageLegacy(v)
	report, err := BridgeValidateMessageBudget(&value, budget)
	if err != nil {
		return s23.LPPAPDU{}, aper.OperationError(err, "LPPAPDUInitiatingMessage")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s23.LPPAPDU{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "LPPAPDUInitiatingMessage")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s23.LPPAPDU{}, aper.OperationError(&s09.BuildError{Issues: issues}, "LPPAPDUInitiatingMessage")
	}
	if _, err := s23.BridgeLPPAPDUMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s23.LPPAPDU{}, aper.OperationError(err, "LPPAPDUInitiatingMessage")
	}
	return value, aper.OperationError(nil, "LPPAPDUInitiatingMessage")
}

// NewLPPAPDUSuccessfulOutcome constructs and validates a complete LPPa message.
func NewLPPAPDUSuccessfulOutcome(v s22.SuccessfulOutcome, options ...aper.BuildOption) (s23.LPPAPDU, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s23.LPPAPDU{}, aper.OperationError(err, "LPPAPDUSuccessfulOutcome")
	}
	value := s23.BridgeNewLPPAPDUSuccessfulOutcomeLegacy(v)
	report, err := BridgeValidateMessageBudget(&value, budget)
	if err != nil {
		return s23.LPPAPDU{}, aper.OperationError(err, "LPPAPDUSuccessfulOutcome")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s23.LPPAPDU{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "LPPAPDUSuccessfulOutcome")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s23.LPPAPDU{}, aper.OperationError(&s09.BuildError{Issues: issues}, "LPPAPDUSuccessfulOutcome")
	}
	if _, err := s23.BridgeLPPAPDUMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s23.LPPAPDU{}, aper.OperationError(err, "LPPAPDUSuccessfulOutcome")
	}
	return value, aper.OperationError(nil, "LPPAPDUSuccessfulOutcome")
}

// NewLPPAPDUUnsuccessfulOutcome constructs and validates a complete LPPa message.
func NewLPPAPDUUnsuccessfulOutcome(v s16.UnsuccessfulOutcome, options ...aper.BuildOption) (s23.LPPAPDU, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s23.LPPAPDU{}, aper.OperationError(err, "LPPAPDUUnsuccessfulOutcome")
	}
	value := s23.BridgeNewLPPAPDUUnsuccessfulOutcomeLegacy(v)
	report, err := BridgeValidateMessageBudget(&value, budget)
	if err != nil {
		return s23.LPPAPDU{}, aper.OperationError(err, "LPPAPDUUnsuccessfulOutcome")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s23.LPPAPDU{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "LPPAPDUUnsuccessfulOutcome")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s23.LPPAPDU{}, aper.OperationError(&s09.BuildError{Issues: issues}, "LPPAPDUUnsuccessfulOutcome")
	}
	if _, err := s23.BridgeLPPAPDUMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s23.LPPAPDU{}, aper.OperationError(err, "LPPAPDUUnsuccessfulOutcome")
	}
	return value, aper.OperationError(nil, "LPPAPDUUnsuccessfulOutcome")
}

type ECIDMeasurementInitiationDescriptor struct{}

func ECIDMeasurementInitiationProcedure() ECIDMeasurementInitiationDescriptor {
	return ECIDMeasurementInitiationDescriptor{}
}

// Info returns the source-derived metadata for this descriptor or binding.
func (ECIDMeasurementInitiationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(2), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-e-CIDMeasurementInitiation"}}}
}

type OTDOAInformationExchangeDescriptor struct{}

func OTDOAInformationExchangeProcedure() OTDOAInformationExchangeDescriptor {
	return OTDOAInformationExchangeDescriptor{}
}

// Info returns the source-derived metadata for this descriptor or binding.
func (OTDOAInformationExchangeDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(6), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-oTDOAInformationExchange"}}}
}

type UTDOAInformationExchangeDescriptor struct{}

func UTDOAInformationExchangeProcedure() UTDOAInformationExchangeDescriptor {
	return UTDOAInformationExchangeDescriptor{}
}

// Info returns the source-derived metadata for this descriptor or binding.
func (UTDOAInformationExchangeDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(7), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-uTDOAInformationExchange"}}}
}

type UTDOAInformationUpdateDescriptor struct{}

func UTDOAInformationUpdateProcedure() UTDOAInformationUpdateDescriptor {
	return UTDOAInformationUpdateDescriptor{}
}

// Info returns the source-derived metadata for this descriptor or binding.
func (UTDOAInformationUpdateDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(8), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-uTDOAInformationUpdate"}}}
}

type AssistanceInformationControlDescriptor struct{}

func AssistanceInformationControlProcedure() AssistanceInformationControlDescriptor {
	return AssistanceInformationControlDescriptor{}
}

// Info returns the source-derived metadata for this descriptor or binding.
func (AssistanceInformationControlDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(9), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-assistanceInformationControl"}}}
}

// AssistanceInformationControlCodec binds the complete APER value type.
func AssistanceInformationControlCodec() s15.AssistanceInformationControlValueCodec {
	return AssistanceInformationControlProcedure().Initiating().Codec()
}

// ECIDMeasurementInitiationFailureCodec binds the complete APER value type.
func ECIDMeasurementInitiationFailureCodec() s11.ECIDMeasurementInitiationFailureValueCodec {
	return ECIDMeasurementInitiationProcedure().Unsuccessful().Codec()
}

// ECIDMeasurementInitiationRequestCodec binds the complete APER value type.
func ECIDMeasurementInitiationRequestCodec() s21.ECIDMeasurementInitiationRequestValueCodec {
	return ECIDMeasurementInitiationProcedure().Initiating().Codec()
}

// ECIDMeasurementInitiationResponseCodec binds the complete APER value type.
func ECIDMeasurementInitiationResponseCodec() s22.ECIDMeasurementInitiationResponseValueCodec {
	return ECIDMeasurementInitiationProcedure().Successful().Codec()
}

// OTDOAInformationFailureCodec binds the complete APER value type.
func OTDOAInformationFailureCodec() s12.OTDOAInformationFailureValueCodec {
	return OTDOAInformationExchangeProcedure().Unsuccessful().Codec()
}

// OTDOAInformationRequestCodec binds the complete APER value type.
func OTDOAInformationRequestCodec() s18.OTDOAInformationRequestValueCodec {
	return OTDOAInformationExchangeProcedure().Initiating().Codec()
}

// OTDOAInformationResponseCodec binds the complete APER value type.
func OTDOAInformationResponseCodec() s18.OTDOAInformationResponseValueCodec {
	return OTDOAInformationExchangeProcedure().Successful().Codec()
}

// UTDOAInformationFailureCodec binds the complete APER value type.
func UTDOAInformationFailureCodec() s16.UTDOAInformationFailureValueCodec {
	return UTDOAInformationExchangeProcedure().Unsuccessful().Codec()
}

// UTDOAInformationRequestCodec binds the complete APER value type.
func UTDOAInformationRequestCodec() s16.UTDOAInformationRequestValueCodec {
	return UTDOAInformationExchangeProcedure().Initiating().Codec()
}

// UTDOAInformationResponseCodec binds the complete APER value type.
func UTDOAInformationResponseCodec() s17.UTDOAInformationResponseValueCodec {
	return UTDOAInformationExchangeProcedure().Successful().Codec()
}

// UTDOAInformationUpdateCodec binds the complete APER value type.
func UTDOAInformationUpdateCodec() s17.UTDOAInformationUpdateValueCodec {
	return UTDOAInformationUpdateProcedure().Initiating().Codec()
}
func BridgeValidateECIDMeasurementInitiationRequestBudget(v *s21.ECIDMeasurementInitiationRequest, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ECIDMeasurementInitiationRequest")
	}
	rows := []s00.FieldInfo{s21.ECIDMeasurementInitiationRequestIEs().ESMLCUEMeasurementID().Info(), s21.ECIDMeasurementInitiationRequestIEs().ReportCharacteristics().Info(), s21.ECIDMeasurementInitiationRequestIEs().MeasurementPeriodicity().Info(), s21.ECIDMeasurementInitiationRequestIEs().MeasurementQuantities().Info(), s21.ECIDMeasurementInitiationRequestIEs().InterRATMeasurementQuantities().Info(), s21.ECIDMeasurementInitiationRequestIEs().WLANMeasurementQuantities().Info()}
	report := s21.BridgeECIDMeasurementInitiationRequestIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "ECIDMeasurementInitiationRequest.protocolIEs", budget)
	BridgeWalkValidationECIDMeasurementInitiationRequest(v, &report, "ECIDMeasurementInitiationRequest", true)
	return report, nil
}
func BridgeValidateECIDMeasurementInitiationResponseBudget(v *s22.ECIDMeasurementInitiationResponse, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ECIDMeasurementInitiationResponse")
	}
	rows := []s00.FieldInfo{s22.ECIDMeasurementInitiationResponseIEs().ESMLCUEMeasurementID().Info(), s22.ECIDMeasurementInitiationResponseIEs().ENBUEMeasurementID().Info(), s22.ECIDMeasurementInitiationResponseIEs().ECIDMeasurementResult().Info(), s22.ECIDMeasurementInitiationResponseIEs().CriticalityDiagnostics().Info(), s22.ECIDMeasurementInitiationResponseIEs().CellPortionID().Info(), s22.ECIDMeasurementInitiationResponseIEs().InterRATMeasurementResult().Info(), s22.ECIDMeasurementInitiationResponseIEs().WLANMeasurementResult().Info()}
	report := s23.BridgeECIDMeasurementInitiationResponseIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "ECIDMeasurementInitiationResponse.protocolIEs", budget)
	BridgeWalkValidationECIDMeasurementInitiationResponse(v, &report, "ECIDMeasurementInitiationResponse", true)
	return report, nil
}
func BridgeValidateOTDOAInformationResponseBudget(v *s18.OTDOAInformationResponse, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil OTDOAInformationResponse")
	}
	rows := []s00.FieldInfo{s18.OTDOAInformationResponseIEs().OTDOACells().Info(), s18.OTDOAInformationResponseIEs().CriticalityDiagnostics().Info(), s18.OTDOAInformationResponseIEs().AddOTDOACells().Info()}
	report := s18.BridgeOTDOAInformationResponseIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "OTDOAInformationResponse.protocolIEs", budget)
	BridgeWalkValidationOTDOAInformationResponse(v, &report, "OTDOAInformationResponse", true)
	return report, nil
}
func BridgeValidateUTDOAInformationRequestBudget(v *s16.UTDOAInformationRequest, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UTDOAInformationRequest")
	}
	rows := []s00.FieldInfo{s09.UTDOAInformationRequestIEs().RequestedSRSTransmissionCharacteristics().Info()}
	report := s16.BridgeUTDOAInformationRequestIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "UTDOAInformationRequest.protocolIEs", budget)
	BridgeWalkValidationUTDOAInformationRequest(v, &report, "UTDOAInformationRequest", true)
	return report, nil
}
func BridgeValidateUTDOAInformationResponseBudget(v *s17.UTDOAInformationResponse, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UTDOAInformationResponse")
	}
	rows := []s00.FieldInfo{s10.UTDOAInformationResponseIEs().ULConfiguration().Info(), s10.UTDOAInformationResponseIEs().CriticalityDiagnostics().Info()}
	report := s17.BridgeUTDOAInformationResponseIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "UTDOAInformationResponse.protocolIEs", budget)
	BridgeWalkValidationUTDOAInformationResponse(v, &report, "UTDOAInformationResponse", true)
	return report, nil
}
func BridgeValidateUTDOAInformationFailureBudget(v *s16.UTDOAInformationFailure, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UTDOAInformationFailure")
	}
	rows := []s00.FieldInfo{s10.UTDOAInformationFailureIEs().Cause().Info(), s10.UTDOAInformationFailureIEs().CriticalityDiagnostics().Info()}
	report := s16.BridgeUTDOAInformationFailureIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "UTDOAInformationFailure.protocolIEs", budget)
	BridgeWalkValidationUTDOAInformationFailure(v, &report, "UTDOAInformationFailure", true)
	return report, nil
}
func BridgeValidateUTDOAInformationUpdateBudget(v *s17.UTDOAInformationUpdate, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UTDOAInformationUpdate")
	}
	rows := []s00.FieldInfo{s11.UTDOAInformationUpdateIEs().ULConfiguration().Info()}
	report := s17.BridgeUTDOAInformationUpdateIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "UTDOAInformationUpdate.protocolIEs", budget)
	BridgeWalkValidationUTDOAInformationUpdate(v, &report, "UTDOAInformationUpdate", true)
	return report, nil
}
func BridgeValidateAssistanceInformationControlBudget(v *s15.AssistanceInformationControl, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil AssistanceInformationControl")
	}
	rows := []s00.FieldInfo{s14.AssistanceInformationControlIEs().AssistanceInformation().Info(), s14.AssistanceInformationControlIEs().Broadcast().Info()}
	report := s15.BridgeAssistanceInformationControlIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "AssistanceInformationControl.protocolIEs", budget)
	BridgeWalkValidationAssistanceInformationControl(v, &report, "AssistanceInformationControl", true)
	return report, nil
}
func BridgeValidateInitiatingMessage(v *s21.InitiatingMessage, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil InitiatingMessage")
	}
	if *s21.BridgeInitiatingValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "InitiatingMessage"}}}})
			return report
		}(), nil
	}
	switch v.ProcedureCode {
	case 0:
		body, ok := v.Value.AsErrorIndication()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ErrorIndication", "InitiatingMessage.value:")
		}
		report, err := s23.BridgeValidateErrorIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s23.ErrorIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 1:
		body, ok := v.Value.AsPrivateMessage()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing PrivateMessage", "InitiatingMessage.value:")
		}
		report, err := s20.BridgeValidatePrivateMessageBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s21.PrivateMessageProcedure().Info().Rule}})
		}
		return report, nil
	case 2:
		body, ok := v.Value.AsECIDMeasurementInitiationRequest()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ECIDMeasurementInitiationRequest", "InitiatingMessage.value:")
		}
		report, err := BridgeValidateECIDMeasurementInitiationRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{ECIDMeasurementInitiationProcedure().Info().Rule}})
		}
		return report, nil
	case 3:
		body, ok := v.Value.AsECIDMeasurementFailureIndication()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ECIDMeasurementFailureIndication", "InitiatingMessage.value:")
		}
		report, err := s23.BridgeValidateECIDMeasurementFailureIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s23.ECIDMeasurementFailureIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 4:
		body, ok := v.Value.AsECIDMeasurementReport()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ECIDMeasurementReport", "InitiatingMessage.value:")
		}
		report, err := s23.BridgeValidateECIDMeasurementReportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s23.ECIDMeasurementReportProcedure().Info().Rule}})
		}
		return report, nil
	case 5:
		body, ok := v.Value.AsECIDMeasurementTerminationCommand()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ECIDMeasurementTerminationCommand", "InitiatingMessage.value:")
		}
		report, err := s23.BridgeValidateECIDMeasurementTerminationCommandBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s23.ECIDMeasurementTerminationProcedure().Info().Rule}})
		}
		return report, nil
	case 6:
		body, ok := v.Value.AsOTDOAInformationRequest()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing OTDOAInformationRequest", "InitiatingMessage.value:")
		}
		report, err := s23.BridgeValidateOTDOAInformationRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{OTDOAInformationExchangeProcedure().Info().Rule}})
		}
		return report, nil
	case 7:
		body, ok := v.Value.AsUTDOAInformationRequest()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UTDOAInformationRequest", "InitiatingMessage.value:")
		}
		report, err := BridgeValidateUTDOAInformationRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UTDOAInformationExchangeProcedure().Info().Rule}})
		}
		return report, nil
	case 8:
		body, ok := v.Value.AsUTDOAInformationUpdate()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UTDOAInformationUpdate", "InitiatingMessage.value:")
		}
		report, err := BridgeValidateUTDOAInformationUpdateBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UTDOAInformationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 9:
		body, ok := v.Value.AsAssistanceInformationControl()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing AssistanceInformationControl", "InitiatingMessage.value:")
		}
		report, err := BridgeValidateAssistanceInformationControlBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{AssistanceInformationControlProcedure().Info().Rule}})
		}
		return report, nil
	case 10:
		body, ok := v.Value.AsAssistanceInformationFeedback()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing AssistanceInformationFeedback", "InitiatingMessage.value:")
		}
		report, err := s23.BridgeValidateAssistanceInformationFeedbackBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s23.AssistanceInformationFeedbackProcedure().Info().Rule}})
		}
		return report, nil
	default:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnknownProcedure, Severity: s00.ValidationSeverityUnrecognized, Location: aper.Location{Path: "InitiatingMessage.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnknownProcedure)})
			s09.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "InitiatingMessage.value"})
			return report
		}(), nil
	}
}
func BridgeValidateSuccessfulOutcome(v *s22.SuccessfulOutcome, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil SuccessfulOutcome")
	}
	if *s22.BridgeSuccessfulValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "SuccessfulOutcome"}}}})
			return report
		}(), nil
	}
	switch v.ProcedureCode {
	case 0:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 1:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 2:
		body, ok := v.Value.AsECIDMeasurementInitiationResponse()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ECIDMeasurementInitiationResponse", "SuccessfulOutcome.value:")
		}
		report, err := BridgeValidateECIDMeasurementInitiationResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{ECIDMeasurementInitiationProcedure().Info().Rule}})
		}
		return report, nil
	case 3:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 4:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 5:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 6:
		body, ok := v.Value.AsOTDOAInformationResponse()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing OTDOAInformationResponse", "SuccessfulOutcome.value:")
		}
		report, err := BridgeValidateOTDOAInformationResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{OTDOAInformationExchangeProcedure().Info().Rule}})
		}
		return report, nil
	case 7:
		body, ok := v.Value.AsUTDOAInformationResponse()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UTDOAInformationResponse", "SuccessfulOutcome.value:")
		}
		report, err := BridgeValidateUTDOAInformationResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UTDOAInformationExchangeProcedure().Info().Rule}})
		}
		return report, nil
	case 8:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 9:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 10:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	default:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnknownProcedure, Severity: s00.ValidationSeverityUnrecognized, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnknownProcedure)})
			s09.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "SuccessfulOutcome.value"})
			return report
		}(), nil
	}
}
func BridgeValidateUnsuccessfulOutcome(v *s16.UnsuccessfulOutcome, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UnsuccessfulOutcome")
	}
	if *s16.BridgeUnsuccessfulValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "UnsuccessfulOutcome"}}}})
			return report
		}(), nil
	}
	switch v.ProcedureCode {
	case 0:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 1:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 2:
		body, ok := v.Value.AsECIDMeasurementInitiationFailure()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing ECIDMeasurementInitiationFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s23.BridgeValidateECIDMeasurementInitiationFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{ECIDMeasurementInitiationProcedure().Info().Rule}})
		}
		return report, nil
	case 3:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 4:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 5:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 6:
		body, ok := v.Value.AsOTDOAInformationFailure()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing OTDOAInformationFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := s23.BridgeValidateOTDOAInformationFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{OTDOAInformationExchangeProcedure().Info().Rule}})
		}
		return report, nil
	case 7:
		body, ok := v.Value.AsUTDOAInformationFailure()
		if !ok {
			return func() s09.ValidationReport {
				sealed := s09.ValidationReport{}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}(), fmt.Errorf("%s missing UTDOAInformationFailure", "UnsuccessfulOutcome.value:")
		}
		report, err := BridgeValidateUTDOAInformationFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UTDOAInformationExchangeProcedure().Info().Rule}})
		}
		return report, nil
	case 8:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 9:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 10:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnavailableOutcome), RelatedRules: s04.BridgeLppaHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	default:
		return func() s09.ValidationReport {
			report := func() s09.ValidationReport {
				sealed := s09.ValidationReport{Complete: false}
				*s09.BridgeValidationReportFieldBudget(&sealed) = budget
				return sealed
			}()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.UnknownProcedure, Severity: s00.ValidationSeverityUnrecognized, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s04.BridgeLppaValidationRule(s00.UnknownProcedure)})
			s09.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "UnsuccessfulOutcome.value"})
			return report
		}(), nil
	}
}
func BridgeValidateMessageBudget(v *s23.LPPAPDU, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil LPPAPDU")
	}
	switch v.Choice {
	case s00.LPPAPDUChoiceInitiatingMessage:
		return BridgeValidateInitiatingMessage(v.InitiatingMessage, budget)
	case s00.LPPAPDUChoiceSuccessfulOutcome:
		return BridgeValidateSuccessfulOutcome(v.SuccessfulOutcome, budget)
	case s00.LPPAPDUChoiceUnsuccessfulOutcome:
		return BridgeValidateUnsuccessfulOutcome(v.UnsuccessfulOutcome, budget)
	default:
		if v.UnknownExtension != nil {
			return func() s09.ValidationReport {
				report := func() s09.ValidationReport {
					sealed := s09.ValidationReport{Complete: false}
					*s09.BridgeValidationReportFieldBudget(&sealed) = budget
					return sealed
				}()
				s09.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "LPPAPDU.unknownExtension"})
				return report
			}(), nil
		}
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("%s invalid choice %d", "LPPAPDU:", v.Choice)
	}
}
func ValidateECIDMeasurementInitiationRequest(v *s21.ECIDMeasurementInitiationRequest, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "ECIDMeasurementInitiationRequest")
	}
	report, err := BridgeValidateECIDMeasurementInitiationRequestBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s21.BridgeECIDMeasurementInitiationRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ECIDMeasurementInitiationRequest")
}
func ValidateECIDMeasurementInitiationResponse(v *s22.ECIDMeasurementInitiationResponse, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "ECIDMeasurementInitiationResponse")
	}
	report, err := BridgeValidateECIDMeasurementInitiationResponseBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s22.BridgeECIDMeasurementInitiationResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ECIDMeasurementInitiationResponse")
}
func ValidateOTDOAInformationResponse(v *s18.OTDOAInformationResponse, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "OTDOAInformationResponse")
	}
	report, err := BridgeValidateOTDOAInformationResponseBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s18.BridgeOTDOAInformationResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "OTDOAInformationResponse")
}
func ValidateUTDOAInformationRequest(v *s16.UTDOAInformationRequest, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "UTDOAInformationRequest")
	}
	report, err := BridgeValidateUTDOAInformationRequestBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s16.BridgeUTDOAInformationRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UTDOAInformationRequest")
}
func ValidateUTDOAInformationResponse(v *s17.UTDOAInformationResponse, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "UTDOAInformationResponse")
	}
	report, err := BridgeValidateUTDOAInformationResponseBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s17.BridgeUTDOAInformationResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UTDOAInformationResponse")
}
func ValidateUTDOAInformationFailure(v *s16.UTDOAInformationFailure, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "UTDOAInformationFailure")
	}
	report, err := BridgeValidateUTDOAInformationFailureBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s16.BridgeUTDOAInformationFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UTDOAInformationFailure")
}
func ValidateUTDOAInformationUpdate(v *s17.UTDOAInformationUpdate, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "UTDOAInformationUpdate")
	}
	report, err := BridgeValidateUTDOAInformationUpdateBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s17.BridgeUTDOAInformationUpdateMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UTDOAInformationUpdate")
}
func ValidateAssistanceInformationControl(v *s15.AssistanceInformationControl, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "AssistanceInformationControl")
	}
	report, err := BridgeValidateAssistanceInformationControlBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s15.BridgeAssistanceInformationControlMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "AssistanceInformationControl")
}
func ValidateMessage(v *s23.LPPAPDU, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "Message")
	}
	report, err := BridgeValidateMessageBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s23.BridgeLPPAPDUMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "Message")
}
func BridgeWalkValidationAddOTDOACellInformation(v *s15.AddOTDOACellInformation, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationOTDOACellInformationItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationAddOTDOACells(v *s15.AddOTDOACells, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationAddOTDOACellsElem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationAddOTDOACellsElem(v *s15.AddOTDOACellsElem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationAddOTDOACellInformation(&v.AddOTDOACellInfo, report, path+".add-OTDOACellInfo", false)
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s09.BridgeAddOTDOACellsExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationAssistanceInformation(v *s14.AssistanceInformation, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationSystemInformation(&v.SystemInformation, report, path+".systemInformation", false)
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s09.BridgeAssistanceInformationExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationAssistanceInformationControl(v *s15.AssistanceInformationControl, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s14.AssistanceInformationControlIEs().AssistanceInformation().Info(), s14.AssistanceInformationControlIEs().Broadcast().Info()}
			s11.BridgeMergeNestedValidation(report, s15.BridgeAssistanceInformationControlIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(22):
				if value, ok := fields[i].Value.AsAssistanceInformation(); ok {
					BridgeWalkValidationAssistanceInformation(value, report, fmt.Sprintf("%s[%d]{id=22}", nestedPath, i), false)
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECIDMeasurementInitiationRequest(v *s21.ECIDMeasurementInitiationRequest, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s21.ECIDMeasurementInitiationRequestIEs().ESMLCUEMeasurementID().Info(), s21.ECIDMeasurementInitiationRequestIEs().ReportCharacteristics().Info(), s21.ECIDMeasurementInitiationRequestIEs().MeasurementPeriodicity().Info(), s21.ECIDMeasurementInitiationRequestIEs().MeasurementQuantities().Info(), s21.ECIDMeasurementInitiationRequestIEs().InterRATMeasurementQuantities().Info(), s21.ECIDMeasurementInitiationRequestIEs().WLANMeasurementQuantities().Info()}
			s11.BridgeMergeNestedValidation(report, s21.BridgeECIDMeasurementInitiationRequestIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(5):
				if value, ok := fields[i].Value.AsMeasurementQuantities(); ok {
					s23.BridgeWalkValidationMeasurementQuantities(value, report, fmt.Sprintf("%s[%d]{id=5}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(15):
				if value, ok := fields[i].Value.AsInterRATMeasurementQuantities(); ok {
					s23.BridgeWalkValidationInterRATMeasurementQuantities(value, report, fmt.Sprintf("%s[%d]{id=15}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(19):
				if value, ok := fields[i].Value.AsWLANMeasurementQuantities(); ok {
					BridgeWalkValidationWLANMeasurementQuantities(value, report, fmt.Sprintf("%s[%d]{id=19}", nestedPath, i), false)
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECIDMeasurementInitiationResponse(v *s22.ECIDMeasurementInitiationResponse, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s22.ECIDMeasurementInitiationResponseIEs().ESMLCUEMeasurementID().Info(), s22.ECIDMeasurementInitiationResponseIEs().ENBUEMeasurementID().Info(), s22.ECIDMeasurementInitiationResponseIEs().ECIDMeasurementResult().Info(), s22.ECIDMeasurementInitiationResponseIEs().CriticalityDiagnostics().Info(), s22.ECIDMeasurementInitiationResponseIEs().CellPortionID().Info(), s22.ECIDMeasurementInitiationResponseIEs().InterRATMeasurementResult().Info(), s22.ECIDMeasurementInitiationResponseIEs().WLANMeasurementResult().Info()}
			s11.BridgeMergeNestedValidation(report, s23.BridgeECIDMeasurementInitiationResponseIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(7):
				if value, ok := fields[i].Value.AsECIDMeasurementResult(); ok {
					s23.BridgeWalkValidationECIDMeasurementResult(value, report, fmt.Sprintf("%s[%d]{id=7}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s23.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(17):
				if value, ok := fields[i].Value.AsInterRATMeasurementResult(); ok {
					s23.BridgeWalkValidationInterRATMeasurementResult(value, report, fmt.Sprintf("%s[%d]{id=17}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(21):
				if value, ok := fields[i].Value.AsWLANMeasurementResult(); ok {
					BridgeWalkValidationWLANMeasurementResult(value, report, fmt.Sprintf("%s[%d]{id=21}", nestedPath, i), false)
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLPPAPDU(v *s23.LPPAPDU, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.LPPAPDUChoiceInitiatingMessage {
		if v.InitiatingMessage != nil {
			s23.BridgeWalkValidationInitiatingMessage(v.InitiatingMessage, report, path+".initiatingMessage", false)
		}
	}
	if v.Choice == s00.LPPAPDUChoiceSuccessfulOutcome {
		if v.SuccessfulOutcome != nil {
			BridgeWalkValidationSuccessfulOutcome(v.SuccessfulOutcome, report, path+".successfulOutcome", false)
		}
	}
	if v.Choice == s00.LPPAPDUChoiceUnsuccessfulOutcome {
		if v.UnsuccessfulOutcome != nil {
			BridgeWalkValidationUnsuccessfulOutcome(v.UnsuccessfulOutcome, report, path+".unsuccessfulOutcome", false)
		}
	}
}
func BridgeWalkValidationMBSFNsubframeConfiguration(v *s09.MBSFNsubframeConfiguration, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationMBSFNsubframeConfigurationValue(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationMBSFNsubframeConfigurationValue(v *s09.MBSFNsubframeConfigurationValue, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationSubframeallocation(&v.SubframeAllocation, report, path+".subframeAllocation", false)
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationOTDOACellInformation(v *s15.OTDOACellInformation, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationOTDOACellInformationItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationOTDOACellInformationItem(v *s15.OTDOACellInformationItem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.OTDOACellInformationItemChoiceCellId {
		if v.CellId != nil {
			s23.BridgeWalkValidationECGI(v.CellId, report, path+".cellId", false)
		}
	}
	if v.Choice == s00.OTDOACellInformationItemChoiceEUTRANAccessPointPosition {
		if v.EUTRANAccessPointPosition != nil {
			s23.BridgeWalkValidationEUTRANAccessPointPosition(v.EUTRANAccessPointPosition, report, path+".e-UTRANAccessPointPosition", false)
		}
	}
	if v.Choice == s00.OTDOACellInformationItemChoicePRSMutingConfiguration {
		if v.PRSMutingConfiguration != nil {
			s23.BridgeWalkValidationPRSMutingConfiguration(v.PRSMutingConfiguration, report, path+".pRSMutingConfiguration", false)
		}
	}
	if v.Choice == s00.OTDOACellInformationItemChoiceMBSFNsubframeConfiguration {
		if v.MBSFNsubframeConfiguration != nil {
			BridgeWalkValidationMBSFNsubframeConfiguration(&v.MBSFNsubframeConfiguration, report, path+".mBSFNsubframeConfiguration", false)
		}
	}
	if v.Choice == s00.OTDOACellInformationItemChoiceNPRSConfiguration {
		if v.NPRSConfiguration != nil {
			s23.BridgeWalkValidationNPRSConfiguration(v.NPRSConfiguration, report, path+".nPRSConfiguration", false)
		}
	}
	if v.Choice == s00.OTDOACellInformationItemChoicePRSFreqHoppingConfig {
		if v.PRSFreqHoppingConfig != nil {
			s23.BridgeWalkValidationPRSFrequencyHoppingConfiguration(v.PRSFreqHoppingConfig, report, path+".pRSFreqHoppingConfig", false)
		}
	}
	if v.Choice == s00.OTDOACellInformationItemChoiceNPRSType2 {
		if v.NPRSType2 != nil {
			s23.BridgeWalkValidationNPRSConfiguration(v.NPRSType2, report, path+".nPRSType2", false)
		}
	}
	if v.Choice == s00.OTDOACellInformationItemChoiceTddConfiguration {
		if v.TddConfiguration != nil {
			BridgeWalkValidationTDDConfiguration(v.TddConfiguration, report, path+".tddConfiguration", false)
		}
	}
}
func BridgeWalkValidationOTDOACells(v *s16.OTDOACells, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationOTDOACellsElem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationOTDOACellsElem(v *s16.OTDOACellsElem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationOTDOACellInformation(&v.OTDOACellInfo, report, path+".oTDOACellInfo", false)
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s12.BridgeOTDOACellsExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationOTDOAInformationResponse(v *s18.OTDOAInformationResponse, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s18.OTDOAInformationResponseIEs().OTDOACells().Info(), s18.OTDOAInformationResponseIEs().CriticalityDiagnostics().Info(), s18.OTDOAInformationResponseIEs().AddOTDOACells().Info()}
			s11.BridgeMergeNestedValidation(report, s18.BridgeOTDOAInformationResponseIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(8):
				if value, ok := fields[i].Value.AsOTDOACells(); ok {
					BridgeWalkValidationOTDOACells(value, report, fmt.Sprintf("%s[%d]{id=8}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s23.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(18):
				if value, ok := fields[i].Value.AsAddOTDOACells(); ok {
					BridgeWalkValidationAddOTDOACells(value, report, fmt.Sprintf("%s[%d]{id=18}", nestedPath, i), false)
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSubframeallocation(v *s09.Subframeallocation, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationSuccessfulOutcome(v *s22.SuccessfulOutcome, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSystemInformation(v *s14.SystemInformation, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationSystemInformationElem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationSystemInformationElem(v *s14.SystemInformationElem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s23.BridgeWalkValidationPosSIBs(&v.PosSIBs, report, path+".posSIBs", false)
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s15.BridgeSystemInformationExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTDDConfiguration(v *s15.TDDConfiguration, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s16.BridgeTDDConfigurationExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationULConfiguration(v *s10.ULConfiguration, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s23.BridgeWalkValidationSRSConfigurationForAllCells(&v.SrsConfiguration, report, path+".srsConfiguration", false)
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUTDOAInformationFailure(v *s16.UTDOAInformationFailure, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s10.UTDOAInformationFailureIEs().Cause().Info(), s10.UTDOAInformationFailureIEs().CriticalityDiagnostics().Info()}
			s11.BridgeMergeNestedValidation(report, s16.BridgeUTDOAInformationFailureIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(0):
				if value, ok := fields[i].Value.AsCause(); ok {
					s23.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=0}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s23.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUTDOAInformationRequest(v *s16.UTDOAInformationRequest, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s09.UTDOAInformationRequestIEs().RequestedSRSTransmissionCharacteristics().Info()}
			s11.BridgeMergeNestedValidation(report, s16.BridgeUTDOAInformationRequestIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(12):
				if value, ok := fields[i].Value.AsRequestedSRSTransmissionCharacteristics(); ok {
					s23.BridgeWalkValidationRequestedSRSTransmissionCharacteristics(value, report, fmt.Sprintf("%s[%d]{id=12}", nestedPath, i), false)
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUTDOAInformationResponse(v *s17.UTDOAInformationResponse, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s10.UTDOAInformationResponseIEs().ULConfiguration().Info(), s10.UTDOAInformationResponseIEs().CriticalityDiagnostics().Info()}
			s11.BridgeMergeNestedValidation(report, s17.BridgeUTDOAInformationResponseIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(13):
				if value, ok := fields[i].Value.AsULConfiguration(); ok {
					BridgeWalkValidationULConfiguration(value, report, fmt.Sprintf("%s[%d]{id=13}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s23.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUTDOAInformationUpdate(v *s17.UTDOAInformationUpdate, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s11.UTDOAInformationUpdateIEs().ULConfiguration().Info()}
			s11.BridgeMergeNestedValidation(report, s17.BridgeUTDOAInformationUpdateIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(13):
				if value, ok := fields[i].Value.AsULConfiguration(); ok {
					BridgeWalkValidationULConfiguration(value, report, fmt.Sprintf("%s[%d]{id=13}", nestedPath, i), false)
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUnsuccessfulOutcome(v *s16.UnsuccessfulOutcome, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationWLANChannelList(v *s00.WLANChannelList, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationWLANMeasurementQuantities(v *s20.WLANMeasurementQuantities, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s20.WLANMeasurementQuantitiesItemIEs().WLANMeasurementQuantitiesItem().Info()}
		s11.BridgeMergeNestedValidation(report, s21.BridgeWLANMeasurementQuantitiesItemIEValueValidateLPPaIEContainer(s20.WLANMeasurementQuantitiesItemIEContainer{field}, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		fields := s20.WLANMeasurementQuantitiesItemIEContainer{field}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(20):
				if value, ok := fields[i].Value.AsWLANMeasurementQuantitiesItem(); ok {
					BridgeWalkValidationWLANMeasurementQuantitiesItem(value, report, fmt.Sprintf("%s[%d]{id=20}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationWLANMeasurementQuantitiesItem(v *s20.WLANMeasurementQuantitiesItem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s21.BridgeWLANMeasurementQuantitiesValueExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationWLANMeasurementResult(v *s22.WLANMeasurementResult, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationWLANMeasurementResultItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationWLANMeasurementResultItem(v *s22.WLANMeasurementResultItem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.WLANChannelList != nil {
		BridgeWalkValidationWLANChannelList(&v.WLANChannelList, report, path+".wLANChannelList", false)
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s23.BridgeWLANMeasurementResultItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
