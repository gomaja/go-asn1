// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s50 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s50

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	s34 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s34"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s38 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s38"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s45 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s45"
	s46 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s46"
	s47 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s47"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func NewHandoverRequired(fields s34.HandoverRequiredIEContainer, options ...aper.BuildOption) (s34.HandoverRequired, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s34.HandoverRequired{}, aper.OperationError(err, "HandoverRequired")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s34.HandoverRequiredIEField](bb, uint64(len(fields))); err != nil {
		return s34.HandoverRequired{}, aper.OperationError(err, "HandoverRequired")
	}
	v := s34.HandoverRequired{ProtocolIEs: make(s34.HandoverRequiredIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverRequiredBudget(&v, budget)
	if err != nil {
		return s34.HandoverRequired{}, aper.OperationError(err, "HandoverRequired")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s34.HandoverRequired{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "HandoverRequired")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s34.HandoverRequired{}, aper.OperationError(&s21.BuildError{Issues: issues}, "HandoverRequired")
	}
	if _, err := s34.BridgeHandoverRequiredMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s34.HandoverRequired{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverRequired.protocolIEs:", err), "HandoverRequired")
	}
	return v, aper.OperationError(nil, "HandoverRequired")
}
func NewHandoverRequest(fields s48.HandoverRequestIEContainer, options ...aper.BuildOption) (s49.HandoverRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s49.HandoverRequest{}, aper.OperationError(err, "HandoverRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s48.HandoverRequestIEField](bb, uint64(len(fields))); err != nil {
		return s49.HandoverRequest{}, aper.OperationError(err, "HandoverRequest")
	}
	v := s49.HandoverRequest{ProtocolIEs: make(s48.HandoverRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverRequestBudget(&v, budget)
	if err != nil {
		return s49.HandoverRequest{}, aper.OperationError(err, "HandoverRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s49.HandoverRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "HandoverRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s49.HandoverRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "HandoverRequest")
	}
	if _, err := s49.BridgeHandoverRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s49.HandoverRequest{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverRequest.protocolIEs:", err), "HandoverRequest")
	}
	return v, aper.OperationError(nil, "HandoverRequest")
}
func NewHandoverNotify(fields s35.HandoverNotifyIEContainer, options ...aper.BuildOption) (s35.HandoverNotify, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s35.HandoverNotify{}, aper.OperationError(err, "HandoverNotify")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s35.HandoverNotifyIEField](bb, uint64(len(fields))); err != nil {
		return s35.HandoverNotify{}, aper.OperationError(err, "HandoverNotify")
	}
	v := s35.HandoverNotify{ProtocolIEs: make(s35.HandoverNotifyIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverNotifyBudget(&v, budget)
	if err != nil {
		return s35.HandoverNotify{}, aper.OperationError(err, "HandoverNotify")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s35.HandoverNotify{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "HandoverNotify")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s35.HandoverNotify{}, aper.OperationError(&s21.BuildError{Issues: issues}, "HandoverNotify")
	}
	if _, err := s35.BridgeHandoverNotifyMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s35.HandoverNotify{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverNotify.protocolIEs:", err), "HandoverNotify")
	}
	return v, aper.OperationError(nil, "HandoverNotify")
}
func NewPathSwitchRequest(fields s41.PathSwitchRequestIEContainer, options ...aper.BuildOption) (s41.PathSwitchRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s41.PathSwitchRequest{}, aper.OperationError(err, "PathSwitchRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s41.PathSwitchRequestIEField](bb, uint64(len(fields))); err != nil {
		return s41.PathSwitchRequest{}, aper.OperationError(err, "PathSwitchRequest")
	}
	v := s41.PathSwitchRequest{ProtocolIEs: make(s41.PathSwitchRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidatePathSwitchRequestBudget(&v, budget)
	if err != nil {
		return s41.PathSwitchRequest{}, aper.OperationError(err, "PathSwitchRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s41.PathSwitchRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "PathSwitchRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s41.PathSwitchRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "PathSwitchRequest")
	}
	if _, err := s41.BridgePathSwitchRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s41.PathSwitchRequest{}, aper.OperationError(fmt.Errorf("%s %w", "PathSwitchRequest.protocolIEs:", err), "PathSwitchRequest")
	}
	return v, aper.OperationError(nil, "PathSwitchRequest")
}
func NewPathSwitchRequestAcknowledge(fields s46.PathSwitchRequestAcknowledgeIEContainer, options ...aper.BuildOption) (s47.PathSwitchRequestAcknowledge, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s47.PathSwitchRequestAcknowledge{}, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s46.PathSwitchRequestAcknowledgeIEField](bb, uint64(len(fields))); err != nil {
		return s47.PathSwitchRequestAcknowledge{}, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	v := s47.PathSwitchRequestAcknowledge{ProtocolIEs: make(s46.PathSwitchRequestAcknowledgeIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidatePathSwitchRequestAcknowledgeBudget(&v, budget)
	if err != nil {
		return s47.PathSwitchRequestAcknowledge{}, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s47.PathSwitchRequestAcknowledge{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "PathSwitchRequestAcknowledge")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s47.PathSwitchRequestAcknowledge{}, aper.OperationError(&s21.BuildError{Issues: issues}, "PathSwitchRequestAcknowledge")
	}
	if _, err := s47.BridgePathSwitchRequestAcknowledgeMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s47.PathSwitchRequestAcknowledge{}, aper.OperationError(fmt.Errorf("%s %w", "PathSwitchRequestAcknowledge.protocolIEs:", err), "PathSwitchRequestAcknowledge")
	}
	return v, aper.OperationError(nil, "PathSwitchRequestAcknowledge")
}
func NewERABSetupRequest(fields s40.ERABSetupRequestIEContainer, options ...aper.BuildOption) (s40.ERABSetupRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s40.ERABSetupRequest{}, aper.OperationError(err, "ERABSetupRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s40.ERABSetupRequestIEField](bb, uint64(len(fields))); err != nil {
		return s40.ERABSetupRequest{}, aper.OperationError(err, "ERABSetupRequest")
	}
	v := s40.ERABSetupRequest{ProtocolIEs: make(s40.ERABSetupRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABSetupRequestBudget(&v, budget)
	if err != nil {
		return s40.ERABSetupRequest{}, aper.OperationError(err, "ERABSetupRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s40.ERABSetupRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ERABSetupRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s40.ERABSetupRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ERABSetupRequest")
	}
	if _, err := s40.BridgeERABSetupRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s40.ERABSetupRequest{}, aper.OperationError(fmt.Errorf("%s %w", "ERABSetupRequest.protocolIEs:", err), "ERABSetupRequest")
	}
	return v, aper.OperationError(nil, "ERABSetupRequest")
}
func NewERABSetupResponse(fields s45.ERABSetupResponseIEContainer, options ...aper.BuildOption) (s46.ERABSetupResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.ERABSetupResponse{}, aper.OperationError(err, "ERABSetupResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s45.ERABSetupResponseIEField](bb, uint64(len(fields))); err != nil {
		return s46.ERABSetupResponse{}, aper.OperationError(err, "ERABSetupResponse")
	}
	v := s46.ERABSetupResponse{ProtocolIEs: make(s45.ERABSetupResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABSetupResponseBudget(&v, budget)
	if err != nil {
		return s46.ERABSetupResponse{}, aper.OperationError(err, "ERABSetupResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s46.ERABSetupResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ERABSetupResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.ERABSetupResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ERABSetupResponse")
	}
	if _, err := s46.BridgeERABSetupResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.ERABSetupResponse{}, aper.OperationError(fmt.Errorf("%s %w", "ERABSetupResponse.protocolIEs:", err), "ERABSetupResponse")
	}
	return v, aper.OperationError(nil, "ERABSetupResponse")
}
func NewERABModifyRequest(fields s40.ERABModifyRequestIEContainer, options ...aper.BuildOption) (s40.ERABModifyRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s40.ERABModifyRequest{}, aper.OperationError(err, "ERABModifyRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s40.ERABModifyRequestIEField](bb, uint64(len(fields))); err != nil {
		return s40.ERABModifyRequest{}, aper.OperationError(err, "ERABModifyRequest")
	}
	v := s40.ERABModifyRequest{ProtocolIEs: make(s40.ERABModifyRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABModifyRequestBudget(&v, budget)
	if err != nil {
		return s40.ERABModifyRequest{}, aper.OperationError(err, "ERABModifyRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s40.ERABModifyRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ERABModifyRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s40.ERABModifyRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ERABModifyRequest")
	}
	if _, err := s40.BridgeERABModifyRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s40.ERABModifyRequest{}, aper.OperationError(fmt.Errorf("%s %w", "ERABModifyRequest.protocolIEs:", err), "ERABModifyRequest")
	}
	return v, aper.OperationError(nil, "ERABModifyRequest")
}
func NewERABModifyResponse(fields s45.ERABModifyResponseIEContainer, options ...aper.BuildOption) (s46.ERABModifyResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.ERABModifyResponse{}, aper.OperationError(err, "ERABModifyResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s45.ERABModifyResponseIEField](bb, uint64(len(fields))); err != nil {
		return s46.ERABModifyResponse{}, aper.OperationError(err, "ERABModifyResponse")
	}
	v := s46.ERABModifyResponse{ProtocolIEs: make(s45.ERABModifyResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABModifyResponseBudget(&v, budget)
	if err != nil {
		return s46.ERABModifyResponse{}, aper.OperationError(err, "ERABModifyResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s46.ERABModifyResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ERABModifyResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.ERABModifyResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ERABModifyResponse")
	}
	if _, err := s46.BridgeERABModifyResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.ERABModifyResponse{}, aper.OperationError(fmt.Errorf("%s %w", "ERABModifyResponse.protocolIEs:", err), "ERABModifyResponse")
	}
	return v, aper.OperationError(nil, "ERABModifyResponse")
}
func NewERABReleaseCommand(fields s39.ERABReleaseCommandIEContainer, options ...aper.BuildOption) (s39.ERABReleaseCommand, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s39.ERABReleaseCommand{}, aper.OperationError(err, "ERABReleaseCommand")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s39.ERABReleaseCommandIEField](bb, uint64(len(fields))); err != nil {
		return s39.ERABReleaseCommand{}, aper.OperationError(err, "ERABReleaseCommand")
	}
	v := s39.ERABReleaseCommand{ProtocolIEs: make(s39.ERABReleaseCommandIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABReleaseCommandBudget(&v, budget)
	if err != nil {
		return s39.ERABReleaseCommand{}, aper.OperationError(err, "ERABReleaseCommand")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s39.ERABReleaseCommand{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ERABReleaseCommand")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s39.ERABReleaseCommand{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ERABReleaseCommand")
	}
	if _, err := s39.BridgeERABReleaseCommandMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s39.ERABReleaseCommand{}, aper.OperationError(fmt.Errorf("%s %w", "ERABReleaseCommand.protocolIEs:", err), "ERABReleaseCommand")
	}
	return v, aper.OperationError(nil, "ERABReleaseCommand")
}
func NewERABReleaseResponse(fields s45.ERABReleaseResponseIEContainer, options ...aper.BuildOption) (s46.ERABReleaseResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.ERABReleaseResponse{}, aper.OperationError(err, "ERABReleaseResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s45.ERABReleaseResponseIEField](bb, uint64(len(fields))); err != nil {
		return s46.ERABReleaseResponse{}, aper.OperationError(err, "ERABReleaseResponse")
	}
	v := s46.ERABReleaseResponse{ProtocolIEs: make(s45.ERABReleaseResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABReleaseResponseBudget(&v, budget)
	if err != nil {
		return s46.ERABReleaseResponse{}, aper.OperationError(err, "ERABReleaseResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s46.ERABReleaseResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ERABReleaseResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.ERABReleaseResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ERABReleaseResponse")
	}
	if _, err := s46.BridgeERABReleaseResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.ERABReleaseResponse{}, aper.OperationError(fmt.Errorf("%s %w", "ERABReleaseResponse.protocolIEs:", err), "ERABReleaseResponse")
	}
	return v, aper.OperationError(nil, "ERABReleaseResponse")
}
func NewERABReleaseIndication(fields s45.ERABReleaseIndicationIEContainer, options ...aper.BuildOption) (s46.ERABReleaseIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.ERABReleaseIndication{}, aper.OperationError(err, "ERABReleaseIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s45.ERABReleaseIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s46.ERABReleaseIndication{}, aper.OperationError(err, "ERABReleaseIndication")
	}
	v := s46.ERABReleaseIndication{ProtocolIEs: make(s45.ERABReleaseIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABReleaseIndicationBudget(&v, budget)
	if err != nil {
		return s46.ERABReleaseIndication{}, aper.OperationError(err, "ERABReleaseIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s46.ERABReleaseIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ERABReleaseIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.ERABReleaseIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ERABReleaseIndication")
	}
	if _, err := s46.BridgeERABReleaseIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.ERABReleaseIndication{}, aper.OperationError(fmt.Errorf("%s %w", "ERABReleaseIndication.protocolIEs:", err), "ERABReleaseIndication")
	}
	return v, aper.OperationError(nil, "ERABReleaseIndication")
}
func NewInitialContextSetupRequest(fields s48.InitialContextSetupRequestIEContainer, options ...aper.BuildOption) (s49.InitialContextSetupRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s49.InitialContextSetupRequest{}, aper.OperationError(err, "InitialContextSetupRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s48.InitialContextSetupRequestIEField](bb, uint64(len(fields))); err != nil {
		return s49.InitialContextSetupRequest{}, aper.OperationError(err, "InitialContextSetupRequest")
	}
	v := s49.InitialContextSetupRequest{ProtocolIEs: make(s48.InitialContextSetupRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateInitialContextSetupRequestBudget(&v, budget)
	if err != nil {
		return s49.InitialContextSetupRequest{}, aper.OperationError(err, "InitialContextSetupRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s49.InitialContextSetupRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "InitialContextSetupRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s49.InitialContextSetupRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "InitialContextSetupRequest")
	}
	if _, err := s49.BridgeInitialContextSetupRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s49.InitialContextSetupRequest{}, aper.OperationError(fmt.Errorf("%s %w", "InitialContextSetupRequest.protocolIEs:", err), "InitialContextSetupRequest")
	}
	return v, aper.OperationError(nil, "InitialContextSetupRequest")
}
func NewPaging(fields s49.PagingIEContainer, options ...aper.BuildOption) (s49.Paging, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s49.Paging{}, aper.OperationError(err, "Paging")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s49.PagingIEField](bb, uint64(len(fields))); err != nil {
		return s49.Paging{}, aper.OperationError(err, "Paging")
	}
	v := s49.Paging{ProtocolIEs: make(s49.PagingIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidatePagingBudget(&v, budget)
	if err != nil {
		return s49.Paging{}, aper.OperationError(err, "Paging")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s49.Paging{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Paging")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s49.Paging{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Paging")
	}
	if _, err := s49.BridgePagingMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s49.Paging{}, aper.OperationError(fmt.Errorf("%s %w", "Paging.protocolIEs:", err), "Paging")
	}
	return v, aper.OperationError(nil, "Paging")
}
func NewDownlinkNASTransport(fields s42.DownlinkNASTransportIEContainer, options ...aper.BuildOption) (s42.DownlinkNASTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s42.DownlinkNASTransport{}, aper.OperationError(err, "DownlinkNASTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s42.DownlinkNASTransportIEField](bb, uint64(len(fields))); err != nil {
		return s42.DownlinkNASTransport{}, aper.OperationError(err, "DownlinkNASTransport")
	}
	v := s42.DownlinkNASTransport{ProtocolIEs: make(s42.DownlinkNASTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateDownlinkNASTransportBudget(&v, budget)
	if err != nil {
		return s42.DownlinkNASTransport{}, aper.OperationError(err, "DownlinkNASTransport")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s42.DownlinkNASTransport{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "DownlinkNASTransport")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s42.DownlinkNASTransport{}, aper.OperationError(&s21.BuildError{Issues: issues}, "DownlinkNASTransport")
	}
	if _, err := s42.BridgeDownlinkNASTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s42.DownlinkNASTransport{}, aper.OperationError(fmt.Errorf("%s %w", "DownlinkNASTransport.protocolIEs:", err), "DownlinkNASTransport")
	}
	return v, aper.OperationError(nil, "DownlinkNASTransport")
}
func NewInitialUEMessage(fields s35.InitialUEMessageIEContainer, options ...aper.BuildOption) (s35.InitialUEMessage, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s35.InitialUEMessage{}, aper.OperationError(err, "InitialUEMessage")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s35.InitialUEMessageIEField](bb, uint64(len(fields))); err != nil {
		return s35.InitialUEMessage{}, aper.OperationError(err, "InitialUEMessage")
	}
	v := s35.InitialUEMessage{ProtocolIEs: make(s35.InitialUEMessageIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateInitialUEMessageBudget(&v, budget)
	if err != nil {
		return s35.InitialUEMessage{}, aper.OperationError(err, "InitialUEMessage")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s35.InitialUEMessage{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "InitialUEMessage")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s35.InitialUEMessage{}, aper.OperationError(&s21.BuildError{Issues: issues}, "InitialUEMessage")
	}
	if _, err := s35.BridgeInitialUEMessageMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s35.InitialUEMessage{}, aper.OperationError(fmt.Errorf("%s %w", "InitialUEMessage.protocolIEs:", err), "InitialUEMessage")
	}
	return v, aper.OperationError(nil, "InitialUEMessage")
}
func NewUplinkNASTransport(fields s32.UplinkNASTransportIEContainer, options ...aper.BuildOption) (s44.UplinkNASTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s44.UplinkNASTransport{}, aper.OperationError(err, "UplinkNASTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s32.UplinkNASTransportIEField](bb, uint64(len(fields))); err != nil {
		return s44.UplinkNASTransport{}, aper.OperationError(err, "UplinkNASTransport")
	}
	v := s44.UplinkNASTransport{ProtocolIEs: make(s32.UplinkNASTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUplinkNASTransportBudget(&v, budget)
	if err != nil {
		return s44.UplinkNASTransport{}, aper.OperationError(err, "UplinkNASTransport")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s44.UplinkNASTransport{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UplinkNASTransport")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s44.UplinkNASTransport{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UplinkNASTransport")
	}
	if _, err := s44.BridgeUplinkNASTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s44.UplinkNASTransport{}, aper.OperationError(fmt.Errorf("%s %w", "UplinkNASTransport.protocolIEs:", err), "UplinkNASTransport")
	}
	return v, aper.OperationError(nil, "UplinkNASTransport")
}
func NewReset(fields s36.ResetIEContainer, options ...aper.BuildOption) (s36.Reset, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.Reset{}, aper.OperationError(err, "Reset")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s36.ResetIEField](bb, uint64(len(fields))); err != nil {
		return s36.Reset{}, aper.OperationError(err, "Reset")
	}
	v := s36.Reset{ProtocolIEs: make(s36.ResetIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateResetBudget(&v, budget)
	if err != nil {
		return s36.Reset{}, aper.OperationError(err, "Reset")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s36.Reset{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Reset")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.Reset{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Reset")
	}
	if _, err := s36.BridgeResetMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.Reset{}, aper.OperationError(fmt.Errorf("%s %w", "Reset.protocolIEs:", err), "Reset")
	}
	return v, aper.OperationError(nil, "Reset")
}
func NewResetAcknowledge(fields s44.ResetAcknowledgeIEContainer, options ...aper.BuildOption) (s44.ResetAcknowledge, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s44.ResetAcknowledge{}, aper.OperationError(err, "ResetAcknowledge")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s44.ResetAcknowledgeIEField](bb, uint64(len(fields))); err != nil {
		return s44.ResetAcknowledge{}, aper.OperationError(err, "ResetAcknowledge")
	}
	v := s44.ResetAcknowledge{ProtocolIEs: make(s44.ResetAcknowledgeIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateResetAcknowledgeBudget(&v, budget)
	if err != nil {
		return s44.ResetAcknowledge{}, aper.OperationError(err, "ResetAcknowledge")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s44.ResetAcknowledge{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ResetAcknowledge")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s44.ResetAcknowledge{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ResetAcknowledge")
	}
	if _, err := s44.BridgeResetAcknowledgeMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s44.ResetAcknowledge{}, aper.OperationError(fmt.Errorf("%s %w", "ResetAcknowledge.protocolIEs:", err), "ResetAcknowledge")
	}
	return v, aper.OperationError(nil, "ResetAcknowledge")
}
func NewS1SetupRequest(fields s43.S1SetupRequestIEContainer, options ...aper.BuildOption) (s44.S1SetupRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s44.S1SetupRequest{}, aper.OperationError(err, "S1SetupRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s43.S1SetupRequestIEField](bb, uint64(len(fields))); err != nil {
		return s44.S1SetupRequest{}, aper.OperationError(err, "S1SetupRequest")
	}
	v := s44.S1SetupRequest{ProtocolIEs: make(s43.S1SetupRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateS1SetupRequestBudget(&v, budget)
	if err != nil {
		return s44.S1SetupRequest{}, aper.OperationError(err, "S1SetupRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s44.S1SetupRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "S1SetupRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s44.S1SetupRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "S1SetupRequest")
	}
	if _, err := s44.BridgeS1SetupRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s44.S1SetupRequest{}, aper.OperationError(fmt.Errorf("%s %w", "S1SetupRequest.protocolIEs:", err), "S1SetupRequest")
	}
	return v, aper.OperationError(nil, "S1SetupRequest")
}
func NewS1SetupResponse(fields s43.S1SetupResponseIEContainer, options ...aper.BuildOption) (s43.S1SetupResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s43.S1SetupResponse{}, aper.OperationError(err, "S1SetupResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s43.S1SetupResponseIEField](bb, uint64(len(fields))); err != nil {
		return s43.S1SetupResponse{}, aper.OperationError(err, "S1SetupResponse")
	}
	v := s43.S1SetupResponse{ProtocolIEs: make(s43.S1SetupResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateS1SetupResponseBudget(&v, budget)
	if err != nil {
		return s43.S1SetupResponse{}, aper.OperationError(err, "S1SetupResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s43.S1SetupResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "S1SetupResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s43.S1SetupResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "S1SetupResponse")
	}
	if _, err := s43.BridgeS1SetupResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s43.S1SetupResponse{}, aper.OperationError(fmt.Errorf("%s %w", "S1SetupResponse.protocolIEs:", err), "S1SetupResponse")
	}
	return v, aper.OperationError(nil, "S1SetupResponse")
}
func NewUEContextReleaseRequest(fields s43.UEContextReleaseRequestIEContainer, options ...aper.BuildOption) (s43.UEContextReleaseRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s43.UEContextReleaseRequest{}, aper.OperationError(err, "UEContextReleaseRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s43.UEContextReleaseRequestIEField](bb, uint64(len(fields))); err != nil {
		return s43.UEContextReleaseRequest{}, aper.OperationError(err, "UEContextReleaseRequest")
	}
	v := s43.UEContextReleaseRequest{ProtocolIEs: make(s43.UEContextReleaseRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextReleaseRequestBudget(&v, budget)
	if err != nil {
		return s43.UEContextReleaseRequest{}, aper.OperationError(err, "UEContextReleaseRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s43.UEContextReleaseRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextReleaseRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s43.UEContextReleaseRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextReleaseRequest")
	}
	if _, err := s43.BridgeUEContextReleaseRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s43.UEContextReleaseRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextReleaseRequest.protocolIEs:", err), "UEContextReleaseRequest")
	}
	return v, aper.OperationError(nil, "UEContextReleaseRequest")
}
func NewUplinkS1cdma2000tunnelling(fields s21.UplinkS1cdma2000tunnellingIEContainer, options ...aper.BuildOption) (s44.UplinkS1cdma2000tunnelling, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s44.UplinkS1cdma2000tunnelling{}, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s21.UplinkS1cdma2000tunnellingIEField](bb, uint64(len(fields))); err != nil {
		return s44.UplinkS1cdma2000tunnelling{}, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	v := s44.UplinkS1cdma2000tunnelling{ProtocolIEs: make(s21.UplinkS1cdma2000tunnellingIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUplinkS1cdma2000tunnellingBudget(&v, budget)
	if err != nil {
		return s44.UplinkS1cdma2000tunnelling{}, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s44.UplinkS1cdma2000tunnelling{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UplinkS1cdma2000tunnelling")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s44.UplinkS1cdma2000tunnelling{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UplinkS1cdma2000tunnelling")
	}
	if _, err := s44.BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s44.UplinkS1cdma2000tunnelling{}, aper.OperationError(fmt.Errorf("%s %w", "UplinkS1cdma2000tunnelling.protocolIEs:", err), "UplinkS1cdma2000tunnelling")
	}
	return v, aper.OperationError(nil, "UplinkS1cdma2000tunnelling")
}
func NewUEContextModificationRequest(fields s46.UEContextModificationRequestIEContainer, options ...aper.BuildOption) (s47.UEContextModificationRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s47.UEContextModificationRequest{}, aper.OperationError(err, "UEContextModificationRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s46.UEContextModificationRequestIEField](bb, uint64(len(fields))); err != nil {
		return s47.UEContextModificationRequest{}, aper.OperationError(err, "UEContextModificationRequest")
	}
	v := s47.UEContextModificationRequest{ProtocolIEs: make(s46.UEContextModificationRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextModificationRequestBudget(&v, budget)
	if err != nil {
		return s47.UEContextModificationRequest{}, aper.OperationError(err, "UEContextModificationRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s47.UEContextModificationRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextModificationRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s47.UEContextModificationRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextModificationRequest")
	}
	if _, err := s47.BridgeUEContextModificationRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s47.UEContextModificationRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextModificationRequest.protocolIEs:", err), "UEContextModificationRequest")
	}
	return v, aper.OperationError(nil, "UEContextModificationRequest")
}
func NewUEContextModificationResponse(fields s23.UEContextModificationResponseIEContainer, options ...aper.BuildOption) (s36.UEContextModificationResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.UEContextModificationResponse{}, aper.OperationError(err, "UEContextModificationResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s23.UEContextModificationResponseIEField](bb, uint64(len(fields))); err != nil {
		return s36.UEContextModificationResponse{}, aper.OperationError(err, "UEContextModificationResponse")
	}
	v := s36.UEContextModificationResponse{ProtocolIEs: make(s23.UEContextModificationResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextModificationResponseBudget(&v, budget)
	if err != nil {
		return s36.UEContextModificationResponse{}, aper.OperationError(err, "UEContextModificationResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s36.UEContextModificationResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextModificationResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.UEContextModificationResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextModificationResponse")
	}
	if _, err := s36.BridgeUEContextModificationResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.UEContextModificationResponse{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextModificationResponse.protocolIEs:", err), "UEContextModificationResponse")
	}
	return v, aper.OperationError(nil, "UEContextModificationResponse")
}
func NewUEContextModificationFailure(fields s23.UEContextModificationFailureIEContainer, options ...aper.BuildOption) (s36.UEContextModificationFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.UEContextModificationFailure{}, aper.OperationError(err, "UEContextModificationFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s23.UEContextModificationFailureIEField](bb, uint64(len(fields))); err != nil {
		return s36.UEContextModificationFailure{}, aper.OperationError(err, "UEContextModificationFailure")
	}
	v := s36.UEContextModificationFailure{ProtocolIEs: make(s23.UEContextModificationFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextModificationFailureBudget(&v, budget)
	if err != nil {
		return s36.UEContextModificationFailure{}, aper.OperationError(err, "UEContextModificationFailure")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s36.UEContextModificationFailure{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextModificationFailure")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.UEContextModificationFailure{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextModificationFailure")
	}
	if _, err := s36.BridgeUEContextModificationFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.UEContextModificationFailure{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextModificationFailure.protocolIEs:", err), "UEContextModificationFailure")
	}
	return v, aper.OperationError(nil, "UEContextModificationFailure")
}
func NewUECapabilityInfoIndication(fields s12.UECapabilityInfoIndicationIEContainer, options ...aper.BuildOption) (s36.UECapabilityInfoIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.UECapabilityInfoIndication{}, aper.OperationError(err, "UECapabilityInfoIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UECapabilityInfoIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s36.UECapabilityInfoIndication{}, aper.OperationError(err, "UECapabilityInfoIndication")
	}
	v := s36.UECapabilityInfoIndication{ProtocolIEs: make(s12.UECapabilityInfoIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUECapabilityInfoIndicationBudget(&v, budget)
	if err != nil {
		return s36.UECapabilityInfoIndication{}, aper.OperationError(err, "UECapabilityInfoIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s36.UECapabilityInfoIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UECapabilityInfoIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.UECapabilityInfoIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UECapabilityInfoIndication")
	}
	if _, err := s36.BridgeUECapabilityInfoIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.UECapabilityInfoIndication{}, aper.OperationError(fmt.Errorf("%s %w", "UECapabilityInfoIndication.protocolIEs:", err), "UECapabilityInfoIndication")
	}
	return v, aper.OperationError(nil, "UECapabilityInfoIndication")
}
func NewUEContextReleaseCommand(fields s37.UEContextReleaseCommandIEContainer, options ...aper.BuildOption) (s37.UEContextReleaseCommand, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s37.UEContextReleaseCommand{}, aper.OperationError(err, "UEContextReleaseCommand")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s37.UEContextReleaseCommandIEField](bb, uint64(len(fields))); err != nil {
		return s37.UEContextReleaseCommand{}, aper.OperationError(err, "UEContextReleaseCommand")
	}
	v := s37.UEContextReleaseCommand{ProtocolIEs: make(s37.UEContextReleaseCommandIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextReleaseCommandBudget(&v, budget)
	if err != nil {
		return s37.UEContextReleaseCommand{}, aper.OperationError(err, "UEContextReleaseCommand")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s37.UEContextReleaseCommand{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextReleaseCommand")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s37.UEContextReleaseCommand{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextReleaseCommand")
	}
	if _, err := s37.BridgeUEContextReleaseCommandMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s37.UEContextReleaseCommand{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextReleaseCommand.protocolIEs:", err), "UEContextReleaseCommand")
	}
	return v, aper.OperationError(nil, "UEContextReleaseCommand")
}
func NewUEContextReleaseComplete(fields s45.UEContextReleaseCompleteIEContainer, options ...aper.BuildOption) (s46.UEContextReleaseComplete, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.UEContextReleaseComplete{}, aper.OperationError(err, "UEContextReleaseComplete")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s45.UEContextReleaseCompleteIEField](bb, uint64(len(fields))); err != nil {
		return s46.UEContextReleaseComplete{}, aper.OperationError(err, "UEContextReleaseComplete")
	}
	v := s46.UEContextReleaseComplete{ProtocolIEs: make(s45.UEContextReleaseCompleteIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextReleaseCompleteBudget(&v, budget)
	if err != nil {
		return s46.UEContextReleaseComplete{}, aper.OperationError(err, "UEContextReleaseComplete")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s46.UEContextReleaseComplete{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextReleaseComplete")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.UEContextReleaseComplete{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextReleaseComplete")
	}
	if _, err := s46.BridgeUEContextReleaseCompleteMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.UEContextReleaseComplete{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextReleaseComplete.protocolIEs:", err), "UEContextReleaseComplete")
	}
	return v, aper.OperationError(nil, "UEContextReleaseComplete")
}
func NewTraceStart(fields s48.TraceStartIEContainer, options ...aper.BuildOption) (s49.TraceStart, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s49.TraceStart{}, aper.OperationError(err, "TraceStart")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s48.TraceStartIEField](bb, uint64(len(fields))); err != nil {
		return s49.TraceStart{}, aper.OperationError(err, "TraceStart")
	}
	v := s49.TraceStart{ProtocolIEs: make(s48.TraceStartIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateTraceStartBudget(&v, budget)
	if err != nil {
		return s49.TraceStart{}, aper.OperationError(err, "TraceStart")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s49.TraceStart{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "TraceStart")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s49.TraceStart{}, aper.OperationError(&s21.BuildError{Issues: issues}, "TraceStart")
	}
	if _, err := s49.BridgeTraceStartMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s49.TraceStart{}, aper.OperationError(fmt.Errorf("%s %w", "TraceStart.protocolIEs:", err), "TraceStart")
	}
	return v, aper.OperationError(nil, "TraceStart")
}
func NewTraceFailureIndication(fields s21.TraceFailureIndicationIEContainer, options ...aper.BuildOption) (s35.TraceFailureIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s35.TraceFailureIndication{}, aper.OperationError(err, "TraceFailureIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s20.TraceFailureIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s35.TraceFailureIndication{}, aper.OperationError(err, "TraceFailureIndication")
	}
	v := s35.TraceFailureIndication{ProtocolIEs: make(s21.TraceFailureIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateTraceFailureIndicationBudget(&v, budget)
	if err != nil {
		return s35.TraceFailureIndication{}, aper.OperationError(err, "TraceFailureIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s35.TraceFailureIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "TraceFailureIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s35.TraceFailureIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "TraceFailureIndication")
	}
	if _, err := s35.BridgeTraceFailureIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s35.TraceFailureIndication{}, aper.OperationError(fmt.Errorf("%s %w", "TraceFailureIndication.protocolIEs:", err), "TraceFailureIndication")
	}
	return v, aper.OperationError(nil, "TraceFailureIndication")
}
func NewENBConfigurationUpdate(fields s43.ENBConfigurationUpdateIEContainer, options ...aper.BuildOption) (s43.ENBConfigurationUpdate, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s43.ENBConfigurationUpdate{}, aper.OperationError(err, "ENBConfigurationUpdate")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s43.ENBConfigurationUpdateIEField](bb, uint64(len(fields))); err != nil {
		return s43.ENBConfigurationUpdate{}, aper.OperationError(err, "ENBConfigurationUpdate")
	}
	v := s43.ENBConfigurationUpdate{ProtocolIEs: make(s43.ENBConfigurationUpdateIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBConfigurationUpdateBudget(&v, budget)
	if err != nil {
		return s43.ENBConfigurationUpdate{}, aper.OperationError(err, "ENBConfigurationUpdate")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s43.ENBConfigurationUpdate{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ENBConfigurationUpdate")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s43.ENBConfigurationUpdate{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ENBConfigurationUpdate")
	}
	if _, err := s43.BridgeENBConfigurationUpdateMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s43.ENBConfigurationUpdate{}, aper.OperationError(fmt.Errorf("%s %w", "ENBConfigurationUpdate.protocolIEs:", err), "ENBConfigurationUpdate")
	}
	return v, aper.OperationError(nil, "ENBConfigurationUpdate")
}
func NewMMEConfigurationUpdate(fields s43.MMEConfigurationUpdateIEContainer, options ...aper.BuildOption) (s43.MMEConfigurationUpdate, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s43.MMEConfigurationUpdate{}, aper.OperationError(err, "MMEConfigurationUpdate")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s43.MMEConfigurationUpdateIEField](bb, uint64(len(fields))); err != nil {
		return s43.MMEConfigurationUpdate{}, aper.OperationError(err, "MMEConfigurationUpdate")
	}
	v := s43.MMEConfigurationUpdate{ProtocolIEs: make(s43.MMEConfigurationUpdateIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEConfigurationUpdateBudget(&v, budget)
	if err != nil {
		return s43.MMEConfigurationUpdate{}, aper.OperationError(err, "MMEConfigurationUpdate")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s43.MMEConfigurationUpdate{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "MMEConfigurationUpdate")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s43.MMEConfigurationUpdate{}, aper.OperationError(&s21.BuildError{Issues: issues}, "MMEConfigurationUpdate")
	}
	if _, err := s43.BridgeMMEConfigurationUpdateMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s43.MMEConfigurationUpdate{}, aper.OperationError(fmt.Errorf("%s %w", "MMEConfigurationUpdate.protocolIEs:", err), "MMEConfigurationUpdate")
	}
	return v, aper.OperationError(nil, "MMEConfigurationUpdate")
}
func NewLocationReport(fields s31.LocationReportIEContainer, options ...aper.BuildOption) (s33.LocationReport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s33.LocationReport{}, aper.OperationError(err, "LocationReport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s31.LocationReportIEField](bb, uint64(len(fields))); err != nil {
		return s33.LocationReport{}, aper.OperationError(err, "LocationReport")
	}
	v := s33.LocationReport{ProtocolIEs: make(s31.LocationReportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateLocationReportBudget(&v, budget)
	if err != nil {
		return s33.LocationReport{}, aper.OperationError(err, "LocationReport")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s33.LocationReport{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "LocationReport")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s33.LocationReport{}, aper.OperationError(&s21.BuildError{Issues: issues}, "LocationReport")
	}
	if _, err := s33.BridgeLocationReportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s33.LocationReport{}, aper.OperationError(fmt.Errorf("%s %w", "LocationReport.protocolIEs:", err), "LocationReport")
	}
	return v, aper.OperationError(nil, "LocationReport")
}
func NewWriteReplaceWarningRequest(fields s33.WriteReplaceWarningRequestIEContainer, options ...aper.BuildOption) (WriteReplaceWarningRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return WriteReplaceWarningRequest{}, aper.OperationError(err, "WriteReplaceWarningRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s33.WriteReplaceWarningRequestIEField](bb, uint64(len(fields))); err != nil {
		return WriteReplaceWarningRequest{}, aper.OperationError(err, "WriteReplaceWarningRequest")
	}
	v := WriteReplaceWarningRequest{ProtocolIEs: make(s33.WriteReplaceWarningRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateWriteReplaceWarningRequestBudget(&v, budget)
	if err != nil {
		return WriteReplaceWarningRequest{}, aper.OperationError(err, "WriteReplaceWarningRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return WriteReplaceWarningRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "WriteReplaceWarningRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return WriteReplaceWarningRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "WriteReplaceWarningRequest")
	}
	if _, err := v.marshalAPERBudget(budget, false); err != nil {
		return WriteReplaceWarningRequest{}, aper.OperationError(fmt.Errorf("%s %w", "WriteReplaceWarningRequest.protocolIEs:", err), "WriteReplaceWarningRequest")
	}
	return v, aper.OperationError(nil, "WriteReplaceWarningRequest")
}
func NewWriteReplaceWarningResponse(fields s32.WriteReplaceWarningResponseIEContainer, options ...aper.BuildOption) (WriteReplaceWarningResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return WriteReplaceWarningResponse{}, aper.OperationError(err, "WriteReplaceWarningResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s32.WriteReplaceWarningResponseIEField](bb, uint64(len(fields))); err != nil {
		return WriteReplaceWarningResponse{}, aper.OperationError(err, "WriteReplaceWarningResponse")
	}
	v := WriteReplaceWarningResponse{ProtocolIEs: make(s32.WriteReplaceWarningResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateWriteReplaceWarningResponseBudget(&v, budget)
	if err != nil {
		return WriteReplaceWarningResponse{}, aper.OperationError(err, "WriteReplaceWarningResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return WriteReplaceWarningResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "WriteReplaceWarningResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return WriteReplaceWarningResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "WriteReplaceWarningResponse")
	}
	if _, err := v.marshalAPERBudget(budget, false); err != nil {
		return WriteReplaceWarningResponse{}, aper.OperationError(fmt.Errorf("%s %w", "WriteReplaceWarningResponse.protocolIEs:", err), "WriteReplaceWarningResponse")
	}
	return v, aper.OperationError(nil, "WriteReplaceWarningResponse")
}
func NewENBDirectInformationTransfer(fields s33.ENBDirectInformationTransferIEContainer, options ...aper.BuildOption) (s34.ENBDirectInformationTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s34.ENBDirectInformationTransfer{}, aper.OperationError(err, "ENBDirectInformationTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s33.ENBDirectInformationTransferIEField](bb, uint64(len(fields))); err != nil {
		return s34.ENBDirectInformationTransfer{}, aper.OperationError(err, "ENBDirectInformationTransfer")
	}
	v := s34.ENBDirectInformationTransfer{ProtocolIEs: make(s33.ENBDirectInformationTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBDirectInformationTransferBudget(&v, budget)
	if err != nil {
		return s34.ENBDirectInformationTransfer{}, aper.OperationError(err, "ENBDirectInformationTransfer")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s34.ENBDirectInformationTransfer{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ENBDirectInformationTransfer")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s34.ENBDirectInformationTransfer{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ENBDirectInformationTransfer")
	}
	if _, err := s34.BridgeENBDirectInformationTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s34.ENBDirectInformationTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "ENBDirectInformationTransfer.protocolIEs:", err), "ENBDirectInformationTransfer")
	}
	return v, aper.OperationError(nil, "ENBDirectInformationTransfer")
}
func NewMMEDirectInformationTransfer(fields s34.MMEDirectInformationTransferIEContainer, options ...aper.BuildOption) (s34.MMEDirectInformationTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s34.MMEDirectInformationTransfer{}, aper.OperationError(err, "MMEDirectInformationTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s34.MMEDirectInformationTransferIEField](bb, uint64(len(fields))); err != nil {
		return s34.MMEDirectInformationTransfer{}, aper.OperationError(err, "MMEDirectInformationTransfer")
	}
	v := s34.MMEDirectInformationTransfer{ProtocolIEs: make(s34.MMEDirectInformationTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEDirectInformationTransferBudget(&v, budget)
	if err != nil {
		return s34.MMEDirectInformationTransfer{}, aper.OperationError(err, "MMEDirectInformationTransfer")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s34.MMEDirectInformationTransfer{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "MMEDirectInformationTransfer")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s34.MMEDirectInformationTransfer{}, aper.OperationError(&s21.BuildError{Issues: issues}, "MMEDirectInformationTransfer")
	}
	if _, err := s34.BridgeMMEDirectInformationTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s34.MMEDirectInformationTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "MMEDirectInformationTransfer.protocolIEs:", err), "MMEDirectInformationTransfer")
	}
	return v, aper.OperationError(nil, "MMEDirectInformationTransfer")
}
func NewKillRequest(fields s33.KillRequestIEContainer, options ...aper.BuildOption) (s33.KillRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s33.KillRequest{}, aper.OperationError(err, "KillRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s33.KillRequestIEField](bb, uint64(len(fields))); err != nil {
		return s33.KillRequest{}, aper.OperationError(err, "KillRequest")
	}
	v := s33.KillRequest{ProtocolIEs: make(s33.KillRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateKillRequestBudget(&v, budget)
	if err != nil {
		return s33.KillRequest{}, aper.OperationError(err, "KillRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s33.KillRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "KillRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s33.KillRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "KillRequest")
	}
	if _, err := s33.BridgeKillRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s33.KillRequest{}, aper.OperationError(fmt.Errorf("%s %w", "KillRequest.protocolIEs:", err), "KillRequest")
	}
	return v, aper.OperationError(nil, "KillRequest")
}
func NewKillResponse(fields s32.KillResponseIEContainer, options ...aper.BuildOption) (s33.KillResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s33.KillResponse{}, aper.OperationError(err, "KillResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s32.KillResponseIEField](bb, uint64(len(fields))); err != nil {
		return s33.KillResponse{}, aper.OperationError(err, "KillResponse")
	}
	v := s33.KillResponse{ProtocolIEs: make(s32.KillResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateKillResponseBudget(&v, budget)
	if err != nil {
		return s33.KillResponse{}, aper.OperationError(err, "KillResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s33.KillResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "KillResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s33.KillResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "KillResponse")
	}
	if _, err := s33.BridgeKillResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s33.KillResponse{}, aper.OperationError(fmt.Errorf("%s %w", "KillResponse.protocolIEs:", err), "KillResponse")
	}
	return v, aper.OperationError(nil, "KillResponse")
}
func NewUplinkUEAssociatedLPPaTransport(fields s12.UplinkUEAssociatedLPPaTransportIEContainer, options ...aper.BuildOption) (s44.UplinkUEAssociatedLPPaTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s44.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UplinkUEAssociatedLPPaTransportIEField](bb, uint64(len(fields))); err != nil {
		return s44.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	v := s44.UplinkUEAssociatedLPPaTransport{ProtocolIEs: make(s12.UplinkUEAssociatedLPPaTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUplinkUEAssociatedLPPaTransportBudget(&v, budget)
	if err != nil {
		return s44.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s44.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UplinkUEAssociatedLPPaTransport")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s44.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UplinkUEAssociatedLPPaTransport")
	}
	if _, err := s44.BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s44.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(fmt.Errorf("%s %w", "UplinkUEAssociatedLPPaTransport.protocolIEs:", err), "UplinkUEAssociatedLPPaTransport")
	}
	return v, aper.OperationError(nil, "UplinkUEAssociatedLPPaTransport")
}
func NewUplinkNonUEAssociatedLPPaTransport(fields s12.UplinkNonUEAssociatedLPPaTransportIEContainer, options ...aper.BuildOption) (s44.UplinkNonUEAssociatedLPPaTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s44.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UplinkNonUEAssociatedLPPaTransportIEField](bb, uint64(len(fields))); err != nil {
		return s44.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	v := s44.UplinkNonUEAssociatedLPPaTransport{ProtocolIEs: make(s12.UplinkNonUEAssociatedLPPaTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUplinkNonUEAssociatedLPPaTransportBudget(&v, budget)
	if err != nil {
		return s44.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s44.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UplinkNonUEAssociatedLPPaTransport")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s44.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UplinkNonUEAssociatedLPPaTransport")
	}
	if _, err := s44.BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s44.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(fmt.Errorf("%s %w", "UplinkNonUEAssociatedLPPaTransport.protocolIEs:", err), "UplinkNonUEAssociatedLPPaTransport")
	}
	return v, aper.OperationError(nil, "UplinkNonUEAssociatedLPPaTransport")
}
func NewUERadioCapabilityMatchRequest(fields s12.UERadioCapabilityMatchRequestIEContainer, options ...aper.BuildOption) (s36.UERadioCapabilityMatchRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.UERadioCapabilityMatchRequest{}, aper.OperationError(err, "UERadioCapabilityMatchRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UERadioCapabilityMatchRequestIEField](bb, uint64(len(fields))); err != nil {
		return s36.UERadioCapabilityMatchRequest{}, aper.OperationError(err, "UERadioCapabilityMatchRequest")
	}
	v := s36.UERadioCapabilityMatchRequest{ProtocolIEs: make(s12.UERadioCapabilityMatchRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUERadioCapabilityMatchRequestBudget(&v, budget)
	if err != nil {
		return s36.UERadioCapabilityMatchRequest{}, aper.OperationError(err, "UERadioCapabilityMatchRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s36.UERadioCapabilityMatchRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UERadioCapabilityMatchRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.UERadioCapabilityMatchRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UERadioCapabilityMatchRequest")
	}
	if _, err := s36.BridgeUERadioCapabilityMatchRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.UERadioCapabilityMatchRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UERadioCapabilityMatchRequest.protocolIEs:", err), "UERadioCapabilityMatchRequest")
	}
	return v, aper.OperationError(nil, "UERadioCapabilityMatchRequest")
}
func NewUERadioCapabilityMatchResponse(fields s24.UERadioCapabilityMatchResponseIEContainer, options ...aper.BuildOption) (s37.UERadioCapabilityMatchResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s37.UERadioCapabilityMatchResponse{}, aper.OperationError(err, "UERadioCapabilityMatchResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s24.UERadioCapabilityMatchResponseIEField](bb, uint64(len(fields))); err != nil {
		return s37.UERadioCapabilityMatchResponse{}, aper.OperationError(err, "UERadioCapabilityMatchResponse")
	}
	v := s37.UERadioCapabilityMatchResponse{ProtocolIEs: make(s24.UERadioCapabilityMatchResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUERadioCapabilityMatchResponseBudget(&v, budget)
	if err != nil {
		return s37.UERadioCapabilityMatchResponse{}, aper.OperationError(err, "UERadioCapabilityMatchResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s37.UERadioCapabilityMatchResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UERadioCapabilityMatchResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s37.UERadioCapabilityMatchResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UERadioCapabilityMatchResponse")
	}
	if _, err := s37.BridgeUERadioCapabilityMatchResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s37.UERadioCapabilityMatchResponse{}, aper.OperationError(fmt.Errorf("%s %w", "UERadioCapabilityMatchResponse.protocolIEs:", err), "UERadioCapabilityMatchResponse")
	}
	return v, aper.OperationError(nil, "UERadioCapabilityMatchResponse")
}
func NewPWSRestartIndication(fields s44.PWSRestartIndicationIEContainer, options ...aper.BuildOption) (s44.PWSRestartIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s44.PWSRestartIndication{}, aper.OperationError(err, "PWSRestartIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s44.PWSRestartIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s44.PWSRestartIndication{}, aper.OperationError(err, "PWSRestartIndication")
	}
	v := s44.PWSRestartIndication{ProtocolIEs: make(s44.PWSRestartIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidatePWSRestartIndicationBudget(&v, budget)
	if err != nil {
		return s44.PWSRestartIndication{}, aper.OperationError(err, "PWSRestartIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s44.PWSRestartIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "PWSRestartIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s44.PWSRestartIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "PWSRestartIndication")
	}
	if _, err := s44.BridgePWSRestartIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s44.PWSRestartIndication{}, aper.OperationError(fmt.Errorf("%s %w", "PWSRestartIndication.protocolIEs:", err), "PWSRestartIndication")
	}
	return v, aper.OperationError(nil, "PWSRestartIndication")
}
func NewERABModificationIndication(fields s44.ERABModificationIndicationIEContainer, options ...aper.BuildOption) (s46.ERABModificationIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.ERABModificationIndication{}, aper.OperationError(err, "ERABModificationIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s44.ERABModificationIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s46.ERABModificationIndication{}, aper.OperationError(err, "ERABModificationIndication")
	}
	v := s46.ERABModificationIndication{ProtocolIEs: make(s44.ERABModificationIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABModificationIndicationBudget(&v, budget)
	if err != nil {
		return s46.ERABModificationIndication{}, aper.OperationError(err, "ERABModificationIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s46.ERABModificationIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ERABModificationIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.ERABModificationIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ERABModificationIndication")
	}
	if _, err := s46.BridgeERABModificationIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.ERABModificationIndication{}, aper.OperationError(fmt.Errorf("%s %w", "ERABModificationIndication.protocolIEs:", err), "ERABModificationIndication")
	}
	return v, aper.OperationError(nil, "ERABModificationIndication")
}
func NewUEContextModificationIndication(fields s21.UEContextModificationIndicationIEContainer, options ...aper.BuildOption) (s36.UEContextModificationIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.UEContextModificationIndication{}, aper.OperationError(err, "UEContextModificationIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s21.UEContextModificationIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s36.UEContextModificationIndication{}, aper.OperationError(err, "UEContextModificationIndication")
	}
	v := s36.UEContextModificationIndication{ProtocolIEs: make(s21.UEContextModificationIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextModificationIndicationBudget(&v, budget)
	if err != nil {
		return s36.UEContextModificationIndication{}, aper.OperationError(err, "UEContextModificationIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s36.UEContextModificationIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextModificationIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.UEContextModificationIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextModificationIndication")
	}
	if _, err := s36.BridgeUEContextModificationIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.UEContextModificationIndication{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextModificationIndication.protocolIEs:", err), "UEContextModificationIndication")
	}
	return v, aper.OperationError(nil, "UEContextModificationIndication")
}
func NewUEContextModificationConfirm(fields s23.UEContextModificationConfirmIEContainer, options ...aper.BuildOption) (s36.UEContextModificationConfirm, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.UEContextModificationConfirm{}, aper.OperationError(err, "UEContextModificationConfirm")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s23.UEContextModificationConfirmIEField](bb, uint64(len(fields))); err != nil {
		return s36.UEContextModificationConfirm{}, aper.OperationError(err, "UEContextModificationConfirm")
	}
	v := s36.UEContextModificationConfirm{ProtocolIEs: make(s23.UEContextModificationConfirmIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextModificationConfirmBudget(&v, budget)
	if err != nil {
		return s36.UEContextModificationConfirm{}, aper.OperationError(err, "UEContextModificationConfirm")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s36.UEContextModificationConfirm{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextModificationConfirm")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.UEContextModificationConfirm{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextModificationConfirm")
	}
	if _, err := s36.BridgeUEContextModificationConfirmMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.UEContextModificationConfirm{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextModificationConfirm.protocolIEs:", err), "UEContextModificationConfirm")
	}
	return v, aper.OperationError(nil, "UEContextModificationConfirm")
}
func NewConnectionEstablishmentIndication(fields s31.ConnectionEstablishmentIndicationIEContainer, options ...aper.BuildOption) (s31.ConnectionEstablishmentIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s31.ConnectionEstablishmentIndication{}, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s31.ConnectionEstablishmentIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s31.ConnectionEstablishmentIndication{}, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	v := s31.ConnectionEstablishmentIndication{ProtocolIEs: make(s31.ConnectionEstablishmentIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateConnectionEstablishmentIndicationBudget(&v, budget)
	if err != nil {
		return s31.ConnectionEstablishmentIndication{}, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s31.ConnectionEstablishmentIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ConnectionEstablishmentIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s31.ConnectionEstablishmentIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ConnectionEstablishmentIndication")
	}
	if _, err := s31.BridgeConnectionEstablishmentIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s31.ConnectionEstablishmentIndication{}, aper.OperationError(fmt.Errorf("%s %w", "ConnectionEstablishmentIndication.protocolIEs:", err), "ConnectionEstablishmentIndication")
	}
	return v, aper.OperationError(nil, "ConnectionEstablishmentIndication")
}
func NewUEContextSuspendRequest(fields s45.UEContextSuspendRequestIEContainer, options ...aper.BuildOption) (s46.UEContextSuspendRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.UEContextSuspendRequest{}, aper.OperationError(err, "UEContextSuspendRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s45.UEContextSuspendRequestIEField](bb, uint64(len(fields))); err != nil {
		return s46.UEContextSuspendRequest{}, aper.OperationError(err, "UEContextSuspendRequest")
	}
	v := s46.UEContextSuspendRequest{ProtocolIEs: make(s45.UEContextSuspendRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextSuspendRequestBudget(&v, budget)
	if err != nil {
		return s46.UEContextSuspendRequest{}, aper.OperationError(err, "UEContextSuspendRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s46.UEContextSuspendRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextSuspendRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.UEContextSuspendRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextSuspendRequest")
	}
	if _, err := s46.BridgeUEContextSuspendRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.UEContextSuspendRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextSuspendRequest.protocolIEs:", err), "UEContextSuspendRequest")
	}
	return v, aper.OperationError(nil, "UEContextSuspendRequest")
}
func NewUEContextSuspendResponse(fields s28.UEContextSuspendResponseIEContainer, options ...aper.BuildOption) (s36.UEContextSuspendResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.UEContextSuspendResponse{}, aper.OperationError(err, "UEContextSuspendResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s28.UEContextSuspendResponseIEField](bb, uint64(len(fields))); err != nil {
		return s36.UEContextSuspendResponse{}, aper.OperationError(err, "UEContextSuspendResponse")
	}
	v := s36.UEContextSuspendResponse{ProtocolIEs: make(s28.UEContextSuspendResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextSuspendResponseBudget(&v, budget)
	if err != nil {
		return s36.UEContextSuspendResponse{}, aper.OperationError(err, "UEContextSuspendResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s36.UEContextSuspendResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextSuspendResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.UEContextSuspendResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextSuspendResponse")
	}
	if _, err := s36.BridgeUEContextSuspendResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.UEContextSuspendResponse{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextSuspendResponse.protocolIEs:", err), "UEContextSuspendResponse")
	}
	return v, aper.OperationError(nil, "UEContextSuspendResponse")
}
func NewUEContextResumeRequest(fields s38.UEContextResumeRequestIEContainer, options ...aper.BuildOption) (s38.UEContextResumeRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s38.UEContextResumeRequest{}, aper.OperationError(err, "UEContextResumeRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s38.UEContextResumeRequestIEField](bb, uint64(len(fields))); err != nil {
		return s38.UEContextResumeRequest{}, aper.OperationError(err, "UEContextResumeRequest")
	}
	v := s38.UEContextResumeRequest{ProtocolIEs: make(s38.UEContextResumeRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextResumeRequestBudget(&v, budget)
	if err != nil {
		return s38.UEContextResumeRequest{}, aper.OperationError(err, "UEContextResumeRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s38.UEContextResumeRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextResumeRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s38.UEContextResumeRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextResumeRequest")
	}
	if _, err := s38.BridgeUEContextResumeRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s38.UEContextResumeRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextResumeRequest.protocolIEs:", err), "UEContextResumeRequest")
	}
	return v, aper.OperationError(nil, "UEContextResumeRequest")
}
func NewUEContextResumeResponse(fields s38.UEContextResumeResponseIEContainer, options ...aper.BuildOption) (s38.UEContextResumeResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s38.UEContextResumeResponse{}, aper.OperationError(err, "UEContextResumeResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s38.UEContextResumeResponseIEField](bb, uint64(len(fields))); err != nil {
		return s38.UEContextResumeResponse{}, aper.OperationError(err, "UEContextResumeResponse")
	}
	v := s38.UEContextResumeResponse{ProtocolIEs: make(s38.UEContextResumeResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextResumeResponseBudget(&v, budget)
	if err != nil {
		return s38.UEContextResumeResponse{}, aper.OperationError(err, "UEContextResumeResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s38.UEContextResumeResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextResumeResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s38.UEContextResumeResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextResumeResponse")
	}
	if _, err := s38.BridgeUEContextResumeResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s38.UEContextResumeResponse{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextResumeResponse.protocolIEs:", err), "UEContextResumeResponse")
	}
	return v, aper.OperationError(nil, "UEContextResumeResponse")
}
func NewUEContextResumeFailure(fields s23.UEContextResumeFailureIEContainer, options ...aper.BuildOption) (s36.UEContextResumeFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.UEContextResumeFailure{}, aper.OperationError(err, "UEContextResumeFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s23.UEContextResumeFailureIEField](bb, uint64(len(fields))); err != nil {
		return s36.UEContextResumeFailure{}, aper.OperationError(err, "UEContextResumeFailure")
	}
	v := s36.UEContextResumeFailure{ProtocolIEs: make(s23.UEContextResumeFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextResumeFailureBudget(&v, budget)
	if err != nil {
		return s36.UEContextResumeFailure{}, aper.OperationError(err, "UEContextResumeFailure")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s36.UEContextResumeFailure{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextResumeFailure")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.UEContextResumeFailure{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextResumeFailure")
	}
	if _, err := s36.BridgeUEContextResumeFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.UEContextResumeFailure{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextResumeFailure.protocolIEs:", err), "UEContextResumeFailure")
	}
	return v, aper.OperationError(nil, "UEContextResumeFailure")
}
func NewUEInformationTransfer(fields s31.UEInformationTransferIEContainer, options ...aper.BuildOption) (s36.UEInformationTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.UEInformationTransfer{}, aper.OperationError(err, "UEInformationTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s31.UEInformationTransferIEField](bb, uint64(len(fields))); err != nil {
		return s36.UEInformationTransfer{}, aper.OperationError(err, "UEInformationTransfer")
	}
	v := s36.UEInformationTransfer{ProtocolIEs: make(s31.UEInformationTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEInformationTransferBudget(&v, budget)
	if err != nil {
		return s36.UEInformationTransfer{}, aper.OperationError(err, "UEInformationTransfer")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s36.UEInformationTransfer{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEInformationTransfer")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.UEInformationTransfer{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEInformationTransfer")
	}
	if _, err := s36.BridgeUEInformationTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.UEInformationTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "UEInformationTransfer.protocolIEs:", err), "UEInformationTransfer")
	}
	return v, aper.OperationError(nil, "UEInformationTransfer")
}
func NewENBCPRelocationIndication(fields s37.ENBCPRelocationIndicationIEContainer, options ...aper.BuildOption) (s37.ENBCPRelocationIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s37.ENBCPRelocationIndication{}, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s37.ENBCPRelocationIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s37.ENBCPRelocationIndication{}, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	v := s37.ENBCPRelocationIndication{ProtocolIEs: make(s37.ENBCPRelocationIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBCPRelocationIndicationBudget(&v, budget)
	if err != nil {
		return s37.ENBCPRelocationIndication{}, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s37.ENBCPRelocationIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ENBCPRelocationIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s37.ENBCPRelocationIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ENBCPRelocationIndication")
	}
	if _, err := s37.BridgeENBCPRelocationIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s37.ENBCPRelocationIndication{}, aper.OperationError(fmt.Errorf("%s %w", "ENBCPRelocationIndication.protocolIEs:", err), "ENBCPRelocationIndication")
	}
	return v, aper.OperationError(nil, "ENBCPRelocationIndication")
}
func NewSecondaryRATDataUsageReport(fields s45.SecondaryRATDataUsageReportIEContainer, options ...aper.BuildOption) (s46.SecondaryRATDataUsageReport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.SecondaryRATDataUsageReport{}, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s45.SecondaryRATDataUsageReportIEField](bb, uint64(len(fields))); err != nil {
		return s46.SecondaryRATDataUsageReport{}, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	v := s46.SecondaryRATDataUsageReport{ProtocolIEs: make(s45.SecondaryRATDataUsageReportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateSecondaryRATDataUsageReportBudget(&v, budget)
	if err != nil {
		return s46.SecondaryRATDataUsageReport{}, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s46.SecondaryRATDataUsageReport{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "SecondaryRATDataUsageReport")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.SecondaryRATDataUsageReport{}, aper.OperationError(&s21.BuildError{Issues: issues}, "SecondaryRATDataUsageReport")
	}
	if _, err := s46.BridgeSecondaryRATDataUsageReportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.SecondaryRATDataUsageReport{}, aper.OperationError(fmt.Errorf("%s %w", "SecondaryRATDataUsageReport.protocolIEs:", err), "SecondaryRATDataUsageReport")
	}
	return v, aper.OperationError(nil, "SecondaryRATDataUsageReport")
}
func NewUERadioCapabilityIDMappingRequest(fields s12.UERadioCapabilityIDMappingRequestIEContainer, options ...aper.BuildOption) (s36.UERadioCapabilityIDMappingRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.UERadioCapabilityIDMappingRequest{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UERadioCapabilityIDMappingRequestIEField](bb, uint64(len(fields))); err != nil {
		return s36.UERadioCapabilityIDMappingRequest{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	v := s36.UERadioCapabilityIDMappingRequest{ProtocolIEs: make(s12.UERadioCapabilityIDMappingRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUERadioCapabilityIDMappingRequestBudget(&v, budget)
	if err != nil {
		return s36.UERadioCapabilityIDMappingRequest{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s36.UERadioCapabilityIDMappingRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UERadioCapabilityIDMappingRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.UERadioCapabilityIDMappingRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UERadioCapabilityIDMappingRequest")
	}
	if _, err := s36.BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.UERadioCapabilityIDMappingRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UERadioCapabilityIDMappingRequest.protocolIEs:", err), "UERadioCapabilityIDMappingRequest")
	}
	return v, aper.OperationError(nil, "UERadioCapabilityIDMappingRequest")
}
func NewUERadioCapabilityIDMappingResponse(fields s24.UERadioCapabilityIDMappingResponseIEContainer, options ...aper.BuildOption) (s36.UERadioCapabilityIDMappingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.UERadioCapabilityIDMappingResponse{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s24.UERadioCapabilityIDMappingResponseIEField](bb, uint64(len(fields))); err != nil {
		return s36.UERadioCapabilityIDMappingResponse{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	v := s36.UERadioCapabilityIDMappingResponse{ProtocolIEs: make(s24.UERadioCapabilityIDMappingResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUERadioCapabilityIDMappingResponseBudget(&v, budget)
	if err != nil {
		return s36.UERadioCapabilityIDMappingResponse{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s36.UERadioCapabilityIDMappingResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UERadioCapabilityIDMappingResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.UERadioCapabilityIDMappingResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UERadioCapabilityIDMappingResponse")
	}
	if _, err := s36.BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.UERadioCapabilityIDMappingResponse{}, aper.OperationError(fmt.Errorf("%s %w", "UERadioCapabilityIDMappingResponse.protocolIEs:", err), "UERadioCapabilityIDMappingResponse")
	}
	return v, aper.OperationError(nil, "UERadioCapabilityIDMappingResponse")
}

// HandoverCommandSuccessfulBinding is the concrete SuccessfulBinding[HandoverCommand].
type HandoverCommandSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s40.HandoverCommand, aper.DecodeState,

	) (s40.HandoverCommand, aper.Snapshot,

	)
	compare func(s40.HandoverCommand, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s40.HandoverCommand,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s40.HandoverCommand,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s40.HandoverCommand,

		error)
	inject func(s40.HandoverCommand,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b HandoverCommandSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCommandSuccessfulBinding) Codec() s40.HandoverCommandValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s40.HandoverCommandValueCodec{}
	}
	return func() s40.HandoverCommandValueCodec {
		sealed := s40.HandoverCommandValueCodec{}
		*s40.BridgeHandoverCommandValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s40.BridgeHandoverCommandValueCodecFieldDecode(&sealed) = b.decode
		*s40.BridgeHandoverCommandValueCodecFieldEncode(&sealed) = func(value s40.HandoverCommand,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s40.BridgeHandoverCommandValueCodecFieldCapture(&sealed) = b.capture
		*s40.BridgeHandoverCommandValueCodecFieldCompare(&sealed) = b.compare
		*s40.BridgeHandoverCommandValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverCommandSuccessfulBinding) Build(body s40.HandoverCommand,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// HandoverRequestAcknowledgeSuccessfulBinding is the concrete SuccessfulBinding[HandoverRequestAcknowledge].
type HandoverRequestAcknowledgeSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s39.HandoverRequestAcknowledge, aper.DecodeState,

	) (s39.HandoverRequestAcknowledge, aper.Snapshot,

	)
	compare func(s39.HandoverRequestAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s39.HandoverRequestAcknowledge,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s39.HandoverRequestAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s39.HandoverRequestAcknowledge,

		error)
	inject func(s39.HandoverRequestAcknowledge,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestAcknowledgeSuccessfulBinding) Codec() s39.HandoverRequestAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s39.HandoverRequestAcknowledgeValueCodec{}
	}
	return func() s39.HandoverRequestAcknowledgeValueCodec {
		sealed := s39.HandoverRequestAcknowledgeValueCodec{}
		*s39.BridgeHandoverRequestAcknowledgeValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s39.BridgeHandoverRequestAcknowledgeValueCodecFieldDecode(&sealed) = b.decode
		*s39.BridgeHandoverRequestAcknowledgeValueCodecFieldEncode(&sealed) = func(value s39.HandoverRequestAcknowledge,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s39.BridgeHandoverRequestAcknowledgeValueCodecFieldCapture(&sealed) = b.capture
		*s39.BridgeHandoverRequestAcknowledgeValueCodecFieldCompare(&sealed) = b.compare
		*s39.BridgeHandoverRequestAcknowledgeValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverRequestAcknowledgeSuccessfulBinding) Build(body s39.HandoverRequestAcknowledge,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// PathSwitchRequestAcknowledgeSuccessfulBinding is the concrete SuccessfulBinding[PathSwitchRequestAcknowledge].
type PathSwitchRequestAcknowledgeSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s47.PathSwitchRequestAcknowledge, aper.DecodeState,

	) (s47.PathSwitchRequestAcknowledge, aper.Snapshot,

	)
	compare func(s47.PathSwitchRequestAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s47.PathSwitchRequestAcknowledge,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s47.PathSwitchRequestAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s47.PathSwitchRequestAcknowledge,

		error)
	inject func(s47.PathSwitchRequestAcknowledge,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeSuccessfulBinding) Codec() s47.PathSwitchRequestAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s47.PathSwitchRequestAcknowledgeValueCodec{}
	}
	return func() s47.PathSwitchRequestAcknowledgeValueCodec {
		sealed := s47.PathSwitchRequestAcknowledgeValueCodec{}
		*s47.BridgePathSwitchRequestAcknowledgeValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s47.BridgePathSwitchRequestAcknowledgeValueCodecFieldDecode(&sealed) = b.decode
		*s47.BridgePathSwitchRequestAcknowledgeValueCodecFieldEncode(&sealed) = func(value s47.PathSwitchRequestAcknowledge,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s47.BridgePathSwitchRequestAcknowledgeValueCodecFieldCapture(&sealed) = b.capture
		*s47.BridgePathSwitchRequestAcknowledgeValueCodecFieldCompare(&sealed) = b.compare
		*s47.BridgePathSwitchRequestAcknowledgeValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b PathSwitchRequestAcknowledgeSuccessfulBinding) Build(body s47.PathSwitchRequestAcknowledge,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// HandoverCancelAcknowledgeSuccessfulBinding is the concrete SuccessfulBinding[HandoverCancelAcknowledge].
type HandoverCancelAcknowledgeSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s25.HandoverCancelAcknowledge, aper.DecodeState,

	) (s25.HandoverCancelAcknowledge, aper.Snapshot,

	)
	compare func(s25.HandoverCancelAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s25.HandoverCancelAcknowledge,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s25.HandoverCancelAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s25.HandoverCancelAcknowledge,

		error)
	inject func(s25.HandoverCancelAcknowledge,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b HandoverCancelAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCancelAcknowledgeSuccessfulBinding) Codec() s25.HandoverCancelAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s25.HandoverCancelAcknowledgeValueCodec{}
	}
	return func() s25.HandoverCancelAcknowledgeValueCodec {
		sealed := s25.HandoverCancelAcknowledgeValueCodec{}
		*s25.BridgeHandoverCancelAcknowledgeValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s25.BridgeHandoverCancelAcknowledgeValueCodecFieldDecode(&sealed) = b.decode
		*s25.BridgeHandoverCancelAcknowledgeValueCodecFieldEncode(&sealed) = func(value s25.HandoverCancelAcknowledge,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s25.BridgeHandoverCancelAcknowledgeValueCodecFieldCapture(&sealed) = b.capture
		*s25.BridgeHandoverCancelAcknowledgeValueCodecFieldCompare(&sealed) = b.compare
		*s25.BridgeHandoverCancelAcknowledgeValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverCancelAcknowledgeSuccessfulBinding) Build(body s25.HandoverCancelAcknowledge,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ERABSetupResponseSuccessfulBinding is the concrete SuccessfulBinding[ERABSetupResponse].
type ERABSetupResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s46.ERABSetupResponse, aper.DecodeState,

	) (s46.ERABSetupResponse, aper.Snapshot,

	)
	compare func(s46.ERABSetupResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s46.ERABSetupResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s46.ERABSetupResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s46.ERABSetupResponse,

		error)
	inject func(s46.ERABSetupResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ERABSetupResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupResponseSuccessfulBinding) Codec() s46.ERABSetupResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.ERABSetupResponseValueCodec{}
	}
	return func() s46.ERABSetupResponseValueCodec {
		sealed := s46.ERABSetupResponseValueCodec{}
		*s46.BridgeERABSetupResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s46.BridgeERABSetupResponseValueCodecFieldDecode(&sealed) = b.decode
		*s46.BridgeERABSetupResponseValueCodecFieldEncode(&sealed) = func(value s46.ERABSetupResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s46.BridgeERABSetupResponseValueCodecFieldCapture(&sealed) = b.capture
		*s46.BridgeERABSetupResponseValueCodecFieldCompare(&sealed) = b.compare
		*s46.BridgeERABSetupResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ERABSetupResponseSuccessfulBinding) Build(body s46.ERABSetupResponse,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ERABModifyResponseSuccessfulBinding is the concrete SuccessfulBinding[ERABModifyResponse].
type ERABModifyResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s46.ERABModifyResponse, aper.DecodeState,

	) (s46.ERABModifyResponse, aper.Snapshot,

	)
	compare func(s46.ERABModifyResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s46.ERABModifyResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s46.ERABModifyResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s46.ERABModifyResponse,

		error)
	inject func(s46.ERABModifyResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ERABModifyResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModifyResponseSuccessfulBinding) Codec() s46.ERABModifyResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.ERABModifyResponseValueCodec{}
	}
	return func() s46.ERABModifyResponseValueCodec {
		sealed := s46.ERABModifyResponseValueCodec{}
		*s46.BridgeERABModifyResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s46.BridgeERABModifyResponseValueCodecFieldDecode(&sealed) = b.decode
		*s46.BridgeERABModifyResponseValueCodecFieldEncode(&sealed) = func(value s46.ERABModifyResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s46.BridgeERABModifyResponseValueCodecFieldCapture(&sealed) = b.capture
		*s46.BridgeERABModifyResponseValueCodecFieldCompare(&sealed) = b.compare
		*s46.BridgeERABModifyResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ERABModifyResponseSuccessfulBinding) Build(body s46.ERABModifyResponse,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ERABReleaseResponseSuccessfulBinding is the concrete SuccessfulBinding[ERABReleaseResponse].
type ERABReleaseResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s46.ERABReleaseResponse, aper.DecodeState,

	) (s46.ERABReleaseResponse, aper.Snapshot,

	)
	compare func(s46.ERABReleaseResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s46.ERABReleaseResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s46.ERABReleaseResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s46.ERABReleaseResponse,

		error)
	inject func(s46.ERABReleaseResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseResponseSuccessfulBinding) Codec() s46.ERABReleaseResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.ERABReleaseResponseValueCodec{}
	}
	return func() s46.ERABReleaseResponseValueCodec {
		sealed := s46.ERABReleaseResponseValueCodec{}
		*s46.BridgeERABReleaseResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s46.BridgeERABReleaseResponseValueCodecFieldDecode(&sealed) = b.decode
		*s46.BridgeERABReleaseResponseValueCodecFieldEncode(&sealed) = func(value s46.ERABReleaseResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s46.BridgeERABReleaseResponseValueCodecFieldCapture(&sealed) = b.capture
		*s46.BridgeERABReleaseResponseValueCodecFieldCompare(&sealed) = b.compare
		*s46.BridgeERABReleaseResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ERABReleaseResponseSuccessfulBinding) Build(body s46.ERABReleaseResponse,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// InitialContextSetupResponseSuccessfulBinding is the concrete SuccessfulBinding[InitialContextSetupResponse].
type InitialContextSetupResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s40.InitialContextSetupResponse, aper.DecodeState,

	) (s40.InitialContextSetupResponse, aper.Snapshot,

	)
	compare func(s40.InitialContextSetupResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s40.InitialContextSetupResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s40.InitialContextSetupResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s40.InitialContextSetupResponse,

		error)
	inject func(s40.InitialContextSetupResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupResponseSuccessfulBinding) Codec() s40.InitialContextSetupResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s40.InitialContextSetupResponseValueCodec{}
	}
	return func() s40.InitialContextSetupResponseValueCodec {
		sealed := s40.InitialContextSetupResponseValueCodec{}
		*s40.BridgeInitialContextSetupResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s40.BridgeInitialContextSetupResponseValueCodecFieldDecode(&sealed) = b.decode
		*s40.BridgeInitialContextSetupResponseValueCodecFieldEncode(&sealed) = func(value s40.InitialContextSetupResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s40.BridgeInitialContextSetupResponseValueCodecFieldCapture(&sealed) = b.capture
		*s40.BridgeInitialContextSetupResponseValueCodecFieldCompare(&sealed) = b.compare
		*s40.BridgeInitialContextSetupResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b InitialContextSetupResponseSuccessfulBinding) Build(body s40.InitialContextSetupResponse,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ResetAcknowledgeSuccessfulBinding is the concrete SuccessfulBinding[ResetAcknowledge].
type ResetAcknowledgeSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s44.ResetAcknowledge, aper.DecodeState,

	) (s44.ResetAcknowledge, aper.Snapshot,

	)
	compare func(s44.ResetAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s44.ResetAcknowledge,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s44.ResetAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s44.ResetAcknowledge,

		error)
	inject func(s44.ResetAcknowledge,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ResetAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ResetAcknowledgeSuccessfulBinding) Codec() s44.ResetAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s44.ResetAcknowledgeValueCodec{}
	}
	return func() s44.ResetAcknowledgeValueCodec {
		sealed := s44.ResetAcknowledgeValueCodec{}
		*s44.BridgeResetAcknowledgeValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s44.BridgeResetAcknowledgeValueCodecFieldDecode(&sealed) = b.decode
		*s44.BridgeResetAcknowledgeValueCodecFieldEncode(&sealed) = func(value s44.ResetAcknowledge,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s44.BridgeResetAcknowledgeValueCodecFieldCapture(&sealed) = b.capture
		*s44.BridgeResetAcknowledgeValueCodecFieldCompare(&sealed) = b.compare
		*s44.BridgeResetAcknowledgeValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ResetAcknowledgeSuccessfulBinding) Build(body s44.ResetAcknowledge,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// S1SetupResponseSuccessfulBinding is the concrete SuccessfulBinding[S1SetupResponse].
type S1SetupResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s43.S1SetupResponse, aper.DecodeState,

	) (s43.S1SetupResponse, aper.Snapshot,

	)
	compare func(s43.S1SetupResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s43.S1SetupResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s43.S1SetupResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s43.S1SetupResponse,

		error)
	inject func(s43.S1SetupResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b S1SetupResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupResponseSuccessfulBinding) Codec() s43.S1SetupResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s43.S1SetupResponseValueCodec{}
	}
	return func() s43.S1SetupResponseValueCodec {
		sealed := s43.S1SetupResponseValueCodec{}
		*s43.BridgeS1SetupResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s43.BridgeS1SetupResponseValueCodecFieldDecode(&sealed) = b.decode
		*s43.BridgeS1SetupResponseValueCodecFieldEncode(&sealed) = func(value s43.S1SetupResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s43.BridgeS1SetupResponseValueCodecFieldCapture(&sealed) = b.capture
		*s43.BridgeS1SetupResponseValueCodecFieldCompare(&sealed) = b.compare
		*s43.BridgeS1SetupResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1SetupResponseSuccessfulBinding) Build(body s43.S1SetupResponse,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextModificationResponseSuccessfulBinding is the concrete SuccessfulBinding[UEContextModificationResponse].
type UEContextModificationResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s36.UEContextModificationResponse, aper.DecodeState,

	) (s36.UEContextModificationResponse, aper.Snapshot,

	)
	compare func(s36.UEContextModificationResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s36.UEContextModificationResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s36.UEContextModificationResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s36.UEContextModificationResponse,

		error)
	inject func(s36.UEContextModificationResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationResponseSuccessfulBinding) Codec() s36.UEContextModificationResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.UEContextModificationResponseValueCodec{}
	}
	return func() s36.UEContextModificationResponseValueCodec {
		sealed := s36.UEContextModificationResponseValueCodec{}
		*s36.BridgeUEContextModificationResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s36.BridgeUEContextModificationResponseValueCodecFieldDecode(&sealed) = b.decode
		*s36.BridgeUEContextModificationResponseValueCodecFieldEncode(&sealed) = func(value s36.UEContextModificationResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s36.BridgeUEContextModificationResponseValueCodecFieldCapture(&sealed) = b.capture
		*s36.BridgeUEContextModificationResponseValueCodecFieldCompare(&sealed) = b.compare
		*s36.BridgeUEContextModificationResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextModificationResponseSuccessfulBinding) Build(body s36.UEContextModificationResponse,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextReleaseCompleteSuccessfulBinding is the concrete SuccessfulBinding[UEContextReleaseComplete].
type UEContextReleaseCompleteSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s46.UEContextReleaseComplete, aper.DecodeState,

	) (s46.UEContextReleaseComplete, aper.Snapshot,

	)
	compare func(s46.UEContextReleaseComplete, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s46.UEContextReleaseComplete,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s46.UEContextReleaseComplete,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s46.UEContextReleaseComplete,

		error)
	inject func(s46.UEContextReleaseComplete,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCompleteSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCompleteSuccessfulBinding) Codec() s46.UEContextReleaseCompleteValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.UEContextReleaseCompleteValueCodec{}
	}
	return func() s46.UEContextReleaseCompleteValueCodec {
		sealed := s46.UEContextReleaseCompleteValueCodec{}
		*s46.BridgeUEContextReleaseCompleteValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s46.BridgeUEContextReleaseCompleteValueCodecFieldDecode(&sealed) = b.decode
		*s46.BridgeUEContextReleaseCompleteValueCodecFieldEncode(&sealed) = func(value s46.UEContextReleaseComplete,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s46.BridgeUEContextReleaseCompleteValueCodecFieldCapture(&sealed) = b.capture
		*s46.BridgeUEContextReleaseCompleteValueCodecFieldCompare(&sealed) = b.compare
		*s46.BridgeUEContextReleaseCompleteValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextReleaseCompleteSuccessfulBinding) Build(body s46.UEContextReleaseComplete,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ENBConfigurationUpdateAcknowledgeSuccessfulBinding is the concrete SuccessfulBinding[ENBConfigurationUpdateAcknowledge].
type ENBConfigurationUpdateAcknowledgeSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s24.ENBConfigurationUpdateAcknowledge, aper.DecodeState,

	) (s24.ENBConfigurationUpdateAcknowledge, aper.Snapshot,

	)
	compare func(s24.ENBConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s24.ENBConfigurationUpdateAcknowledge,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s24.ENBConfigurationUpdateAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s24.ENBConfigurationUpdateAcknowledge,

		error)
	inject func(s24.ENBConfigurationUpdateAcknowledge,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateAcknowledgeSuccessfulBinding) Codec() s24.ENBConfigurationUpdateAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s24.ENBConfigurationUpdateAcknowledgeValueCodec{}
	}
	return func() s24.ENBConfigurationUpdateAcknowledgeValueCodec {
		sealed := s24.ENBConfigurationUpdateAcknowledgeValueCodec{}
		*s24.BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s24.BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldDecode(&sealed) = b.decode
		*s24.BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldEncode(&sealed) = func(value s24.ENBConfigurationUpdateAcknowledge,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s24.BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldCapture(&sealed) = b.capture
		*s24.BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldCompare(&sealed) = b.compare
		*s24.BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ENBConfigurationUpdateAcknowledgeSuccessfulBinding) Build(body s24.ENBConfigurationUpdateAcknowledge,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// MMEConfigurationUpdateAcknowledgeSuccessfulBinding is the concrete SuccessfulBinding[MMEConfigurationUpdateAcknowledge].
type MMEConfigurationUpdateAcknowledgeSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s25.MMEConfigurationUpdateAcknowledge, aper.DecodeState,

	) (s25.MMEConfigurationUpdateAcknowledge, aper.Snapshot,

	)
	compare func(s25.MMEConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s25.MMEConfigurationUpdateAcknowledge,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s25.MMEConfigurationUpdateAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s25.MMEConfigurationUpdateAcknowledge,

		error)
	inject func(s25.MMEConfigurationUpdateAcknowledge,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateAcknowledgeSuccessfulBinding) Codec() s25.MMEConfigurationUpdateAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s25.MMEConfigurationUpdateAcknowledgeValueCodec{}
	}
	return func() s25.MMEConfigurationUpdateAcknowledgeValueCodec {
		sealed := s25.MMEConfigurationUpdateAcknowledgeValueCodec{}
		*s25.BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s25.BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldDecode(&sealed) = b.decode
		*s25.BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldEncode(&sealed) = func(value s25.MMEConfigurationUpdateAcknowledge,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s25.BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldCapture(&sealed) = b.capture
		*s25.BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldCompare(&sealed) = b.compare
		*s25.BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b MMEConfigurationUpdateAcknowledgeSuccessfulBinding) Build(body s25.MMEConfigurationUpdateAcknowledge,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// WriteReplaceWarningResponseSuccessfulBinding is the concrete SuccessfulBinding[WriteReplaceWarningResponse].
type WriteReplaceWarningResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(WriteReplaceWarningResponse, aper.DecodeState,

	) (WriteReplaceWarningResponse, aper.Snapshot,

	)
	compare func(WriteReplaceWarningResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*WriteReplaceWarningResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*WriteReplaceWarningResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (WriteReplaceWarningResponse,

		error)
	inject func(WriteReplaceWarningResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b WriteReplaceWarningResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b WriteReplaceWarningResponseSuccessfulBinding) Codec() WriteReplaceWarningResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return WriteReplaceWarningResponseValueCodec{}
	}
	return WriteReplaceWarningResponseValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value WriteReplaceWarningResponse,

		fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates a body and constructs its bound procedure message.
func (b WriteReplaceWarningResponseSuccessfulBinding) Build(body WriteReplaceWarningResponse,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// KillResponseSuccessfulBinding is the concrete SuccessfulBinding[KillResponse].
type KillResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s33.KillResponse, aper.DecodeState,

	) (s33.KillResponse, aper.Snapshot,

	)
	compare func(s33.KillResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s33.KillResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s33.KillResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s33.KillResponse,

		error)
	inject func(s33.KillResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b KillResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b KillResponseSuccessfulBinding) Codec() s33.KillResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s33.KillResponseValueCodec{}
	}
	return func() s33.KillResponseValueCodec {
		sealed := s33.KillResponseValueCodec{}
		*s33.BridgeKillResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s33.BridgeKillResponseValueCodecFieldDecode(&sealed) = b.decode
		*s33.BridgeKillResponseValueCodecFieldEncode(&sealed) = func(value s33.KillResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s33.BridgeKillResponseValueCodecFieldCapture(&sealed) = b.capture
		*s33.BridgeKillResponseValueCodecFieldCompare(&sealed) = b.compare
		*s33.BridgeKillResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b KillResponseSuccessfulBinding) Build(body s33.KillResponse,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UERadioCapabilityMatchResponseSuccessfulBinding is the concrete SuccessfulBinding[UERadioCapabilityMatchResponse].
type UERadioCapabilityMatchResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s37.UERadioCapabilityMatchResponse, aper.DecodeState,

	) (s37.UERadioCapabilityMatchResponse, aper.Snapshot,

	)
	compare func(s37.UERadioCapabilityMatchResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s37.UERadioCapabilityMatchResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s37.UERadioCapabilityMatchResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s37.UERadioCapabilityMatchResponse,

		error)
	inject func(s37.UERadioCapabilityMatchResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityMatchResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityMatchResponseSuccessfulBinding) Codec() s37.UERadioCapabilityMatchResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s37.UERadioCapabilityMatchResponseValueCodec{}
	}
	return func() s37.UERadioCapabilityMatchResponseValueCodec {
		sealed := s37.UERadioCapabilityMatchResponseValueCodec{}
		*s37.BridgeUERadioCapabilityMatchResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s37.BridgeUERadioCapabilityMatchResponseValueCodecFieldDecode(&sealed) = b.decode
		*s37.BridgeUERadioCapabilityMatchResponseValueCodecFieldEncode(&sealed) = func(value s37.UERadioCapabilityMatchResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s37.BridgeUERadioCapabilityMatchResponseValueCodecFieldCapture(&sealed) = b.capture
		*s37.BridgeUERadioCapabilityMatchResponseValueCodecFieldCompare(&sealed) = b.compare
		*s37.BridgeUERadioCapabilityMatchResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UERadioCapabilityMatchResponseSuccessfulBinding) Build(body s37.UERadioCapabilityMatchResponse,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ERABModificationConfirmSuccessfulBinding is the concrete SuccessfulBinding[ERABModificationConfirm].
type ERABModificationConfirmSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s39.ERABModificationConfirm, aper.DecodeState,

	) (s39.ERABModificationConfirm, aper.Snapshot,

	)
	compare func(s39.ERABModificationConfirm, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s39.ERABModificationConfirm,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s39.ERABModificationConfirm,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s39.ERABModificationConfirm,

		error)
	inject func(s39.ERABModificationConfirm,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ERABModificationConfirmSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModificationConfirmSuccessfulBinding) Codec() s39.ERABModificationConfirmValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s39.ERABModificationConfirmValueCodec{}
	}
	return func() s39.ERABModificationConfirmValueCodec {
		sealed := s39.ERABModificationConfirmValueCodec{}
		*s39.BridgeERABModificationConfirmValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s39.BridgeERABModificationConfirmValueCodecFieldDecode(&sealed) = b.decode
		*s39.BridgeERABModificationConfirmValueCodecFieldEncode(&sealed) = func(value s39.ERABModificationConfirm,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s39.BridgeERABModificationConfirmValueCodecFieldCapture(&sealed) = b.capture
		*s39.BridgeERABModificationConfirmValueCodecFieldCompare(&sealed) = b.compare
		*s39.BridgeERABModificationConfirmValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ERABModificationConfirmSuccessfulBinding) Build(body s39.ERABModificationConfirm,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextModificationConfirmSuccessfulBinding is the concrete SuccessfulBinding[UEContextModificationConfirm].
type UEContextModificationConfirmSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s36.UEContextModificationConfirm, aper.DecodeState,

	) (s36.UEContextModificationConfirm, aper.Snapshot,

	)
	compare func(s36.UEContextModificationConfirm, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s36.UEContextModificationConfirm,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s36.UEContextModificationConfirm,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s36.UEContextModificationConfirm,

		error)
	inject func(s36.UEContextModificationConfirm,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationConfirmSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationConfirmSuccessfulBinding) Codec() s36.UEContextModificationConfirmValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.UEContextModificationConfirmValueCodec{}
	}
	return func() s36.UEContextModificationConfirmValueCodec {
		sealed := s36.UEContextModificationConfirmValueCodec{}
		*s36.BridgeUEContextModificationConfirmValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s36.BridgeUEContextModificationConfirmValueCodecFieldDecode(&sealed) = b.decode
		*s36.BridgeUEContextModificationConfirmValueCodecFieldEncode(&sealed) = func(value s36.UEContextModificationConfirm,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s36.BridgeUEContextModificationConfirmValueCodecFieldCapture(&sealed) = b.capture
		*s36.BridgeUEContextModificationConfirmValueCodecFieldCompare(&sealed) = b.compare
		*s36.BridgeUEContextModificationConfirmValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextModificationConfirmSuccessfulBinding) Build(body s36.UEContextModificationConfirm,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextSuspendResponseSuccessfulBinding is the concrete SuccessfulBinding[UEContextSuspendResponse].
type UEContextSuspendResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s36.UEContextSuspendResponse, aper.DecodeState,

	) (s36.UEContextSuspendResponse, aper.Snapshot,

	)
	compare func(s36.UEContextSuspendResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s36.UEContextSuspendResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s36.UEContextSuspendResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s36.UEContextSuspendResponse,

		error)
	inject func(s36.UEContextSuspendResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendResponseSuccessfulBinding) Codec() s36.UEContextSuspendResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.UEContextSuspendResponseValueCodec{}
	}
	return func() s36.UEContextSuspendResponseValueCodec {
		sealed := s36.UEContextSuspendResponseValueCodec{}
		*s36.BridgeUEContextSuspendResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s36.BridgeUEContextSuspendResponseValueCodecFieldDecode(&sealed) = b.decode
		*s36.BridgeUEContextSuspendResponseValueCodecFieldEncode(&sealed) = func(value s36.UEContextSuspendResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s36.BridgeUEContextSuspendResponseValueCodecFieldCapture(&sealed) = b.capture
		*s36.BridgeUEContextSuspendResponseValueCodecFieldCompare(&sealed) = b.compare
		*s36.BridgeUEContextSuspendResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextSuspendResponseSuccessfulBinding) Build(body s36.UEContextSuspendResponse,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextResumeResponseSuccessfulBinding is the concrete SuccessfulBinding[UEContextResumeResponse].
type UEContextResumeResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s38.UEContextResumeResponse, aper.DecodeState,

	) (s38.UEContextResumeResponse, aper.Snapshot,

	)
	compare func(s38.UEContextResumeResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s38.UEContextResumeResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s38.UEContextResumeResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s38.UEContextResumeResponse,

		error)
	inject func(s38.UEContextResumeResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeResponseSuccessfulBinding) Codec() s38.UEContextResumeResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s38.UEContextResumeResponseValueCodec{}
	}
	return func() s38.UEContextResumeResponseValueCodec {
		sealed := s38.UEContextResumeResponseValueCodec{}
		*s38.BridgeUEContextResumeResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s38.BridgeUEContextResumeResponseValueCodecFieldDecode(&sealed) = b.decode
		*s38.BridgeUEContextResumeResponseValueCodecFieldEncode(&sealed) = func(value s38.UEContextResumeResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s38.BridgeUEContextResumeResponseValueCodecFieldCapture(&sealed) = b.capture
		*s38.BridgeUEContextResumeResponseValueCodecFieldCompare(&sealed) = b.compare
		*s38.BridgeUEContextResumeResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextResumeResponseSuccessfulBinding) Build(body s38.UEContextResumeResponse,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UERadioCapabilityIDMappingResponseSuccessfulBinding is the concrete SuccessfulBinding[UERadioCapabilityIDMappingResponse].
type UERadioCapabilityIDMappingResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s36.UERadioCapabilityIDMappingResponse, aper.DecodeState,

	) (s36.UERadioCapabilityIDMappingResponse, aper.Snapshot,

	)
	compare func(s36.UERadioCapabilityIDMappingResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s36.UERadioCapabilityIDMappingResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s36.UERadioCapabilityIDMappingResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s36.UERadioCapabilityIDMappingResponse,

		error)
	inject func(s36.UERadioCapabilityIDMappingResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityIDMappingResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityIDMappingResponseSuccessfulBinding) Codec() s36.UERadioCapabilityIDMappingResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.UERadioCapabilityIDMappingResponseValueCodec{}
	}
	return func() s36.UERadioCapabilityIDMappingResponseValueCodec {
		sealed := s36.UERadioCapabilityIDMappingResponseValueCodec{}
		*s36.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s36.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldDecode(&sealed) = b.decode
		*s36.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldEncode(&sealed) = func(value s36.UERadioCapabilityIDMappingResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s36.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldCapture(&sealed) = b.capture
		*s36.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldCompare(&sealed) = b.compare
		*s36.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UERadioCapabilityIDMappingResponseSuccessfulBinding) Build(body s36.UERadioCapabilityIDMappingResponse,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// S1RemovalResponseSuccessfulBinding is the concrete SuccessfulBinding[S1RemovalResponse].
type S1RemovalResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s26.S1RemovalResponse, aper.DecodeState,

	) (s26.S1RemovalResponse, aper.Snapshot,

	)
	compare func(s26.S1RemovalResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s26.S1RemovalResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s26.S1RemovalResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s26.S1RemovalResponse,

		error)
	inject func(s26.S1RemovalResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b S1RemovalResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1RemovalResponseSuccessfulBinding) Codec() s26.S1RemovalResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s26.S1RemovalResponseValueCodec{}
	}
	return func() s26.S1RemovalResponseValueCodec {
		sealed := s26.S1RemovalResponseValueCodec{}
		*s26.BridgeS1RemovalResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s26.BridgeS1RemovalResponseValueCodecFieldDecode(&sealed) = b.decode
		*s26.BridgeS1RemovalResponseValueCodecFieldEncode(&sealed) = func(value s26.S1RemovalResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s26.BridgeS1RemovalResponseValueCodecFieldCapture(&sealed) = b.capture
		*s26.BridgeS1RemovalResponseValueCodecFieldCompare(&sealed) = b.compare
		*s26.BridgeS1RemovalResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1RemovalResponseSuccessfulBinding) Build(body s26.S1RemovalResponse,

	options ...aper.BuildOption) (SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}
func BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEContainer(v *s33.WriteReplaceWarningRequestIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEContainer(v *s33.WriteReplaceWarningRequestIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEContainer(v *s32.WriteReplaceWarningResponseIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEContainer(v *s32.WriteReplaceWarningResponseIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeX2TNLConfigurationInfoExtIEsValueCaptureS1APProtocolExtensionContainer(v *s38.X2TNLConfigurationInfoExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeX2TNLConfigurationInfoExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeX2TNLConfigurationInfoExtIEsValueCompareS1APProtocolExtensionContainer(v *s38.X2TNLConfigurationInfoExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeX2TNLConfigurationInfoExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// SONConfigurationTransferExtIEsExtContainer is ProtocolExtensionContainer {{SONConfigurationTransfer-ExtIEs}} of TS 36.413: a list of SONConfigurationTransferExtIEsExtField values.
type SONConfigurationTransferExtIEsExtContainer []SONConfigurationTransferExtIEsExtField

// SONConfigurationTransferExtIEsExtField is ProtocolExtensionField {{SONConfigurationTransfer-ExtIEs}} of TS 36.413: an extension field.
type SONConfigurationTransferExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolExtensionID
	Criticality    s00.Criticality
	ExtensionValue SONConfigurationTransferExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONConfigurationTransferExtIEsExtField) WithoutReplay() SONConfigurationTransferExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SONConfigurationTransferExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SONConfigurationTransferExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
			nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	// TS 36.413 V19.2.0 §9.3.7 binds the table-selected value to @id.
	if !v.ExtensionValue.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.ExtensionValue.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SONConfigurationTransferExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONConfigurationTransferExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero SONConfigurationTransferExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := zero.decode(v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("extension %d: %w", v.Id, err), "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SONConfigurationTransferExtIEsSynchronisationInformationExtBinding binds SynchronisationInformation to the SONConfigurationTransfer-ExtIEs object set of TS 36.413.
type SONConfigurationTransferExtIEsSynchronisationInformationExtBinding struct {
	info   s00.ExtensionInfo
	codec  s31.SynchronisationInformationValueCodec
	inject func(s31.SynchronisationInformation,

	) SONConfigurationTransferExtIEsValue

	get func(*SONConfigurationTransferExtIEsValue,

	) (*s31.SynchronisationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SONConfigurationTransferExtIEsSynchronisationInformationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SONConfigurationTransferExtIEsSynchronisationInformationExtBinding) Codec() s31.SynchronisationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SONConfigurationTransferExtIEsSynchronisationInformationExtBinding) New(value s31.SynchronisationInformation,

) (SONConfigurationTransferExtIEsExtField, error) {
	if b.inject == nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeSynchronisationInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SONConfigurationTransferExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SONConfigurationTransferExtIEsSynchronisationInformationExtBinding) Get(field *SONConfigurationTransferExtIEsExtField) (*s31.SynchronisationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding binds RequestedTNLInfo to the SONConfigurationTransfer-ExtIEs object set of TS 36.413.
type SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding struct {
	info   s00.ExtensionInfo
	codec  s26.RequestedTNLInfoValueCodec
	inject func(s26.RequestedTNLInfo,

	) SONConfigurationTransferExtIEsValue

	get func(*SONConfigurationTransferExtIEsValue,

	) (*s26.RequestedTNLInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding) Codec() s26.RequestedTNLInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding) New(value s26.RequestedTNLInfo,

) (SONConfigurationTransferExtIEsExtField, error) {
	if b.inject == nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s26.BridgeRequestedTNLInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SONConfigurationTransferExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding) Get(field *SONConfigurationTransferExtIEsExtField) (*s26.RequestedTNLInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SuccessfulOutcomeValueCodec is the concrete ValueCodec[SuccessfulOutcome].
type SuccessfulOutcomeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SuccessfulOutcome,

		error)
	encode func(SuccessfulOutcome,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SuccessfulOutcome, aper.DecodeState,

	) (SuccessfulOutcome, aper.Snapshot,

	)
	compare func(SuccessfulOutcome, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SuccessfulOutcomeValueCodec) New(value SuccessfulOutcome,

) (SuccessfulOutcomeAPERValue, error) {
	if c.encode == nil {
		return SuccessfulOutcomeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SuccessfulOutcomeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SuccessfulOutcomeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SuccessfulOutcomeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SuccessfulOutcomeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SuccessfulOutcomeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SuccessfulOutcomeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SuccessfulOutcomeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SuccessfulOutcomeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SuccessfulOutcomeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SuccessfulOutcomeValueCodec) EncodeAPER(value SuccessfulOutcomeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SuccessfulOutcomeValueCodec) encodeBudgetValue(value SuccessfulOutcome,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SuccessfulOutcomeValueCodec) encodeChanged(value SuccessfulOutcome,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WriteReplaceWarningRequestValueCodec is the concrete ValueCodec[WriteReplaceWarningRequest].
type WriteReplaceWarningRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningRequest,

		error)
	encode func(WriteReplaceWarningRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningRequest, aper.DecodeState,

	) (WriteReplaceWarningRequest, aper.Snapshot,

	)
	compare func(WriteReplaceWarningRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningRequestValueCodec) New(value WriteReplaceWarningRequest,

) (WriteReplaceWarningRequestAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningRequestValueCodec) EncodeAPER(value WriteReplaceWarningRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WriteReplaceWarningRequestValueCodec) encodeBudgetValue(value WriteReplaceWarningRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningRequestValueCodec) encodeChanged(value WriteReplaceWarningRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WriteReplaceWarningResponseValueCodec is the concrete ValueCodec[WriteReplaceWarningResponse].
type WriteReplaceWarningResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WriteReplaceWarningResponse,

		error)
	encode func(WriteReplaceWarningResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WriteReplaceWarningResponse, aper.DecodeState,

	) (WriteReplaceWarningResponse, aper.Snapshot,

	)
	compare func(WriteReplaceWarningResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WriteReplaceWarningResponseValueCodec) New(value WriteReplaceWarningResponse,

) (WriteReplaceWarningResponseAPERValue, error) {
	if c.encode == nil {
		return WriteReplaceWarningResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WriteReplaceWarningResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WriteReplaceWarningResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WriteReplaceWarningResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WriteReplaceWarningResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WriteReplaceWarningResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WriteReplaceWarningResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WriteReplaceWarningResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WriteReplaceWarningResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WriteReplaceWarningResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WriteReplaceWarningResponseValueCodec) EncodeAPER(value WriteReplaceWarningResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WriteReplaceWarningResponseValueCodec) encodeBudgetValue(value WriteReplaceWarningResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WriteReplaceWarningResponseValueCodec) encodeChanged(value WriteReplaceWarningResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeWriteReplaceWarningRequestIEValueValidateS1APIEContainer(fields s33.WriteReplaceWarningRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s33.BridgeWriteReplaceWarningRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s33.BridgeWriteReplaceWarningRequestIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s33.BridgeWriteReplaceWarningRequestIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeWriteReplaceWarningResponseIEValueValidateS1APIEContainer(fields s32.WriteReplaceWarningResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s32.BridgeWriteReplaceWarningResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s32.BridgeWriteReplaceWarningResponseIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s32.BridgeWriteReplaceWarningResponseIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s26.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s26.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s26.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// WriteReplaceWarningRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{WriteReplaceWarningRequestIEs}} codec of TS 36.413.
func WriteReplaceWarningRequestIEValueERABIEContainerListCodec(table s00.WriteReplaceWarningRequestIEValueIETable) s33.WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec {
	codec := WriteReplaceWarningRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s33.WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec{}
	}
	return func() s33.WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec {
		sealed := s33.WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec{}
		*s33.BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.WriteReplaceWarningRequestIEValueERABIEContainerList, error) {
			value, err := (*s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s33.WriteReplaceWarningRequestIEValueERABIEContainerList(value), err
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s33.WriteReplaceWarningRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldEncode(&codec))(s33.WriteReplaceWarningRequestIEContainer(value), fresh, budget)
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s33.WriteReplaceWarningRequestIEValueERABIEContainerList, options aper.DecodeState) (s33.WriteReplaceWarningRequestIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s33.WriteReplaceWarningRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{WriteReplaceWarningResponseIEs}} codec of TS 36.413.
func WriteReplaceWarningResponseIEValueERABIEContainerListCodec(table s00.WriteReplaceWarningResponseIEValueIETable) s32.WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec {
	codec := WriteReplaceWarningResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s32.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec{}
	}
	return func() s32.WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec {
		sealed := s32.WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec{}
		*s32.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.WriteReplaceWarningResponseIEValueERABIEContainerList, error) {
			value, err := (*s32.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s32.WriteReplaceWarningResponseIEValueERABIEContainerList(value), err
		}
		*s32.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.WriteReplaceWarningResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldEncode(&codec))(s32.WriteReplaceWarningResponseIEContainer(value), fresh, budget)
		}
		*s32.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.WriteReplaceWarningResponseIEValueERABIEContainerList, options aper.DecodeState) (s32.WriteReplaceWarningResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.WriteReplaceWarningResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// X2TNLConfigurationInfoExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{X2TNLConfigurationInfo-ExtIEs}} codec of TS 36.413.
func X2TNLConfigurationInfoExtIEsValueExtensionFieldTableCodec(table s00.X2TNLConfigurationInfoExtIEsValueExtensionTable) s38.X2TNLConfigurationInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeX2TNLConfigurationInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s38.X2TNLConfigurationInfoExtIEsExtFieldValueCodec{}
	}
	return func() s38.X2TNLConfigurationInfoExtIEsExtFieldValueCodec {
		sealed := s38.X2TNLConfigurationInfoExtIEsExtFieldValueCodec{}
		*s38.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s38.X2TNLConfigurationInfoExtIEsExtField, error) {
			var field s38.X2TNLConfigurationInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s38.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s38.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s38.X2TNLConfigurationInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s38.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s38.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s38.X2TNLConfigurationInfoExtIEsExtField, options aper.DecodeState) (s38.X2TNLConfigurationInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeX2TNLConfigurationInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s38.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s38.X2TNLConfigurationInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeX2TNLConfigurationInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s38.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{WriteReplaceWarningRequestIEs}} codec of TS 36.413.
func WriteReplaceWarningRequestIEValueIEFieldTableCodec(table s00.WriteReplaceWarningRequestIEValueIETable) s33.WriteReplaceWarningRequestIEFieldValueCodec {
	if !*s00.BridgeWriteReplaceWarningRequestIEValueIETableFieldBound(&table) {
		return s33.WriteReplaceWarningRequestIEFieldValueCodec{}
	}
	return func() s33.WriteReplaceWarningRequestIEFieldValueCodec {
		sealed := s33.WriteReplaceWarningRequestIEFieldValueCodec{}
		*s33.BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.WriteReplaceWarningRequestIEField, error) {
			var field s33.WriteReplaceWarningRequestIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s33.BridgeWriteReplaceWarningRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s33.BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldEncode(&sealed) = func(field s33.WriteReplaceWarningRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s33.BridgeWriteReplaceWarningRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s33.BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldCapture(&sealed) = func(v s33.WriteReplaceWarningRequestIEField, options aper.DecodeState) (s33.WriteReplaceWarningRequestIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s33.BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldCompare(&sealed) = func(v s33.WriteReplaceWarningRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{WriteReplaceWarningResponseIEs}} codec of TS 36.413.
func WriteReplaceWarningResponseIEValueIEFieldTableCodec(table s00.WriteReplaceWarningResponseIEValueIETable) s32.WriteReplaceWarningResponseIEFieldValueCodec {
	if !*s00.BridgeWriteReplaceWarningResponseIEValueIETableFieldBound(&table) {
		return s32.WriteReplaceWarningResponseIEFieldValueCodec{}
	}
	return func() s32.WriteReplaceWarningResponseIEFieldValueCodec {
		sealed := s32.WriteReplaceWarningResponseIEFieldValueCodec{}
		*s32.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.WriteReplaceWarningResponseIEField, error) {
			var field s32.WriteReplaceWarningResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s32.BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s32.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s32.WriteReplaceWarningResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s32.BridgeWriteReplaceWarningResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s32.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s32.WriteReplaceWarningResponseIEField, options aper.DecodeState) (s32.WriteReplaceWarningResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s32.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s32.WriteReplaceWarningResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningRequestIEValueIETableCodec constructs the ProtocolIE-Container {{WriteReplaceWarningRequestIEs}} codec of TS 36.413.
func WriteReplaceWarningRequestIEValueIETableCodec(table s00.WriteReplaceWarningRequestIEValueIETable, bounds aper.ListBounds) s33.WriteReplaceWarningRequestIEContainerValueCodec {
	if !*s00.BridgeWriteReplaceWarningRequestIEValueIETableFieldBound(&table) {
		return s33.WriteReplaceWarningRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s33.WriteReplaceWarningRequestIEContainerValueCodec {
		sealed := s33.WriteReplaceWarningRequestIEContainerValueCodec{}
		*s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.WriteReplaceWarningRequestIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s33.WriteReplaceWarningRequestIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s33.WriteReplaceWarningRequestIEField
					if err := s33.BridgeWriteReplaceWarningRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldEncode(&sealed) = func(fields s33.WriteReplaceWarningRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s33.BridgeWriteReplaceWarningRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldCapture(&sealed) = func(v s33.WriteReplaceWarningRequestIEContainer, options aper.DecodeState) (s33.WriteReplaceWarningRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldCompare(&sealed) = func(v s33.WriteReplaceWarningRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningResponseIEValueIETableCodec constructs the ProtocolIE-Container {{WriteReplaceWarningResponseIEs}} codec of TS 36.413.
func WriteReplaceWarningResponseIEValueIETableCodec(table s00.WriteReplaceWarningResponseIEValueIETable, bounds aper.ListBounds) s32.WriteReplaceWarningResponseIEContainerValueCodec {
	if !*s00.BridgeWriteReplaceWarningResponseIEValueIETableFieldBound(&table) {
		return s32.WriteReplaceWarningResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s32.WriteReplaceWarningResponseIEContainerValueCodec {
		sealed := s32.WriteReplaceWarningResponseIEContainerValueCodec{}
		*s32.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.WriteReplaceWarningResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s32.WriteReplaceWarningResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s32.WriteReplaceWarningResponseIEField
					if err := s32.BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
						return err
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s32.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s32.WriteReplaceWarningResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s32.BridgeWriteReplaceWarningResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s32.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s32.WriteReplaceWarningResponseIEContainer, options aper.DecodeState) (s32.WriteReplaceWarningResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s32.WriteReplaceWarningResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{WriteReplaceWarningRequestIEs}} codec of TS 36.413.
func WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListCodec(table s00.WriteReplaceWarningRequestIEValueIETable) s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := WriteReplaceWarningRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec{}
		*s33.BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList(value), err
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldEncode(&codec))(s33.WriteReplaceWarningRequestIEContainer(value), fresh, budget)
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{WriteReplaceWarningResponseIEs}} codec of TS 36.413.
func WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListCodec(table s00.WriteReplaceWarningResponseIEValueIETable) s32.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := WriteReplaceWarningResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s32.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s32.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s32.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s32.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s32.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s32.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList(value), err
		}
		*s32.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldEncode(&codec))(s32.WriteReplaceWarningResponseIEContainer(value), fresh, budget)
		}
		*s32.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s32.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s32.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {WriteReplaceWarningRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func WriteReplaceWarningRequestIEValueProtocolIEContainerListCodec(table s00.WriteReplaceWarningRequestIEValueIETable, bounds aper.ListBounds) s33.WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec {
	codec := WriteReplaceWarningRequestIEValueIETableCodec(table, bounds)
	if *s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s33.WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s33.WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec {
		sealed := s33.WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec{}
		*s33.BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.WriteReplaceWarningRequestIEValueProtocolIEContainerList, error) {
			value, err := (*s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s33.WriteReplaceWarningRequestIEValueProtocolIEContainerList(value), err
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s33.WriteReplaceWarningRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldEncode(&codec))(s33.WriteReplaceWarningRequestIEContainer(value), fresh, budget)
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s33.WriteReplaceWarningRequestIEValueProtocolIEContainerList, options aper.DecodeState) (s33.WriteReplaceWarningRequestIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s33.WriteReplaceWarningRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {WriteReplaceWarningResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func WriteReplaceWarningResponseIEValueProtocolIEContainerListCodec(table s00.WriteReplaceWarningResponseIEValueIETable, bounds aper.ListBounds) s32.WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec {
	codec := WriteReplaceWarningResponseIEValueIETableCodec(table, bounds)
	if *s32.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s32.WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s32.WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s32.WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec{}
		*s32.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s32.WriteReplaceWarningResponseIEValueProtocolIEContainerList, error) {
			value, err := (*s32.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s32.WriteReplaceWarningResponseIEValueProtocolIEContainerList(value), err
		}
		*s32.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s32.WriteReplaceWarningResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s32.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldEncode(&codec))(s32.WriteReplaceWarningResponseIEContainer(value), fresh, budget)
		}
		*s32.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s32.WriteReplaceWarningResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s32.WriteReplaceWarningResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s32.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s32.WriteReplaceWarningResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s32.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// writeReplaceWarningRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s33.WriteReplaceWarningRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s33.WriteReplaceWarningRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEField(v *s33.WriteReplaceWarningRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s33.BridgeWriteReplaceWarningRequestIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s33.BridgeWriteReplaceWarningRequestIEFieldFieldReplay(v), *s33.BridgeWriteReplaceWarningRequestIEFieldFieldWithoutReplay(v))
}
func BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEField(v *s33.WriteReplaceWarningRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s33.BridgeWriteReplaceWarningRequestIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s33.BridgeWriteReplaceWarningRequestIEFieldFieldReplay(v), *s33.BridgeWriteReplaceWarningRequestIEFieldFieldWithoutReplay(v))
}

// writeReplaceWarningResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[WriteReplaceWarningResponseIEValue].
type WriteReplaceWarningResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s32.WriteReplaceWarningResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s32.WriteReplaceWarningResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEField(v *s32.WriteReplaceWarningResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s32.BridgeWriteReplaceWarningResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s32.BridgeWriteReplaceWarningResponseIEFieldFieldReplay(v), *s32.BridgeWriteReplaceWarningResponseIEFieldFieldWithoutReplay(v))
}
func BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEField(v *s32.WriteReplaceWarningResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s32.BridgeWriteReplaceWarningResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s32.BridgeWriteReplaceWarningResponseIEFieldFieldReplay(v), *s32.BridgeWriteReplaceWarningResponseIEFieldFieldWithoutReplay(v))
}
func BridgeX2TNLConfigurationInfoExtIEsValueCaptureS1APProtocolExtensionField(v *s38.X2TNLConfigurationInfoExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s38.BridgeX2TNLConfigurationInfoExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s38.BridgeX2TNLConfigurationInfoExtIEsExtFieldFieldReplay(v), *s38.BridgeX2TNLConfigurationInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeX2TNLConfigurationInfoExtIEsValueCompareS1APProtocolExtensionField(v *s38.X2TNLConfigurationInfoExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s38.BridgeX2TNLConfigurationInfoExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s38.BridgeX2TNLConfigurationInfoExtIEsExtFieldFieldReplay(v), *s38.BridgeX2TNLConfigurationInfoExtIEsExtFieldFieldWithoutReplay(v))
}

// SuccessfulOutcomeAPERValue is the concrete APERValue[SuccessfulOutcome].
type SuccessfulOutcomeAPERValue struct {
	context s00.BridgeCodecContext
	Value   SuccessfulOutcome

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SuccessfulOutcomeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SuccessfulOutcomeAPERValue) WithoutReplay() SuccessfulOutcomeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WriteReplaceWarningRequestAPERValue is the concrete APERValue[WriteReplaceWarningRequest].
type WriteReplaceWarningRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   WriteReplaceWarningRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningRequestAPERValue) WithoutReplay() WriteReplaceWarningRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WriteReplaceWarningResponseAPERValue is the concrete APERValue[WriteReplaceWarningResponse].
type WriteReplaceWarningResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   WriteReplaceWarningResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WriteReplaceWarningResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WriteReplaceWarningResponseAPERValue) WithoutReplay() WriteReplaceWarningResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONConfigurationTransferExtIEsIEField uses the ProtocolIE-Field shape for object set SONConfigurationTransfer-ExtIEs of TS 36.413.
type SONConfigurationTransferExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         SONConfigurationTransferExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONConfigurationTransferExtIEsIEField) WithoutReplay() SONConfigurationTransferExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *SONConfigurationTransferExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *SONConfigurationTransferExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v !=
		nil && bb.
		ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
			nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	// TS 36.413 V19.2.0 §9.3.7 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *SONConfigurationTransferExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONConfigurationTransferExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero SONConfigurationTransferExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	paddingMark := bb.EnterComponent("Value")
	value, err := zero.decode(v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// SONConfigurationTransferExtIEsIEContainer uses the ProtocolIE-Container shape for object set SONConfigurationTransfer-ExtIEs of TS 36.413: a list of SONConfigurationTransferExtIEsIEField values.
type SONConfigurationTransferExtIEsIEContainer []SONConfigurationTransferExtIEsIEField

func BridgeWriteReplaceWarningRequestIEValueCaptureS1APERABIEContainerList(v *s33.WriteReplaceWarningRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeWriteReplaceWarningRequestIEValueCompareS1APERABIEContainerList(v *s33.WriteReplaceWarningRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeWriteReplaceWarningResponseIEValueCaptureS1APERABIEContainerList(v *s32.WriteReplaceWarningResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeWriteReplaceWarningResponseIEValueCompareS1APERABIEContainerList(v *s32.WriteReplaceWarningResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// SONConfigurationTransferExtIEsExtFieldValueCodec is the concrete ValueCodec[SONConfigurationTransferExtIEsExtField].
type SONConfigurationTransferExtIEsExtFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONConfigurationTransferExtIEsExtField, error)
	encode  func(SONConfigurationTransferExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONConfigurationTransferExtIEsExtField, aper.DecodeState) (SONConfigurationTransferExtIEsExtField, aper.Snapshot)
	compare func(SONConfigurationTransferExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONConfigurationTransferExtIEsExtFieldValueCodec) New(value SONConfigurationTransferExtIEsExtField) (SONConfigurationTransferExtIEsExtFieldAPERValue, error) {
	if c.encode == nil {
		return SONConfigurationTransferExtIEsExtFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONConfigurationTransferExtIEsExtFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONConfigurationTransferExtIEsExtFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONConfigurationTransferExtIEsExtFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONConfigurationTransferExtIEsExtFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONConfigurationTransferExtIEsExtFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONConfigurationTransferExtIEsExtFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONConfigurationTransferExtIEsExtFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONConfigurationTransferExtIEsExtFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONConfigurationTransferExtIEsExtFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONConfigurationTransferExtIEsExtFieldValueCodec) EncodeAPER(value SONConfigurationTransferExtIEsExtFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONConfigurationTransferExtIEsExtFieldValueCodec) encodeBudgetValue(value SONConfigurationTransferExtIEsExtField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONConfigurationTransferExtIEsExtFieldValueCodec) encodeChanged(value SONConfigurationTransferExtIEsExtField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONConfigurationTransferExtIEsExtContainerValueCodec is the concrete ValueCodec[SONConfigurationTransferExtIEsExtContainer].
type SONConfigurationTransferExtIEsExtContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONConfigurationTransferExtIEsExtContainer, error)
	encode  func(SONConfigurationTransferExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONConfigurationTransferExtIEsExtContainer, aper.DecodeState) (SONConfigurationTransferExtIEsExtContainer, aper.Snapshot)
	compare func(SONConfigurationTransferExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONConfigurationTransferExtIEsExtContainerValueCodec) New(value SONConfigurationTransferExtIEsExtContainer) (SONConfigurationTransferExtIEsExtContainerAPERValue, error) {
	if c.encode == nil {
		return SONConfigurationTransferExtIEsExtContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONConfigurationTransferExtIEsExtContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONConfigurationTransferExtIEsExtContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONConfigurationTransferExtIEsExtContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONConfigurationTransferExtIEsExtContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONConfigurationTransferExtIEsExtContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONConfigurationTransferExtIEsExtContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONConfigurationTransferExtIEsExtContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONConfigurationTransferExtIEsExtContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONConfigurationTransferExtIEsExtContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONConfigurationTransferExtIEsExtContainerValueCodec) EncodeAPER(value SONConfigurationTransferExtIEsExtContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c SONConfigurationTransferExtIEsExtContainerValueCodec) encodeBudgetValue(value SONConfigurationTransferExtIEsExtContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONConfigurationTransferExtIEsExtContainerValueCodec) encodeChanged(value SONConfigurationTransferExtIEsExtContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolErrorIEContainerList(v *s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s32.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s32.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEContainerList(v *s33.WriteReplaceWarningRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEContainerList(v *s33.WriteReplaceWarningRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEContainerList(v *s32.WriteReplaceWarningResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEContainerList(v *s32.WriteReplaceWarningResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIESingleContainer(v *s33.WriteReplaceWarningRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIESingleContainer(v *s33.WriteReplaceWarningRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIESingleContainer(v *s32.WriteReplaceWarningResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIESingleContainer(v *s32.WriteReplaceWarningResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// SONConfigurationTransferExtIEsExtFieldAPERValue is the concrete APERValue[SONConfigurationTransferExtIEsExtField].
type SONConfigurationTransferExtIEsExtFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SONConfigurationTransferExtIEsExtField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONConfigurationTransferExtIEsExtFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONConfigurationTransferExtIEsExtFieldAPERValue) WithoutReplay() SONConfigurationTransferExtIEsExtFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONConfigurationTransferExtIEsExtContainerAPERValue is the concrete APERValue[SONConfigurationTransferExtIEsExtContainer].
type SONConfigurationTransferExtIEsExtContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         SONConfigurationTransferExtIEsExtContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONConfigurationTransferExtIEsExtContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONConfigurationTransferExtIEsExtContainerAPERValue) WithoutReplay() SONConfigurationTransferExtIEsExtContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

type SuccessfulValue struct {
	code                                   s00.ProcedureCode
	received                               aper.WireSpan
	replay                                 aper.Snapshot
	opaque                                 aper.OpaqueOpenType
	isOpaque                               bool
	bodyHandoverCommand                    *s40.HandoverCommand
	bodyHandoverRequestAcknowledge         *s39.HandoverRequestAcknowledge
	bodyPathSwitchRequestAcknowledge       *s47.PathSwitchRequestAcknowledge
	bodyHandoverCancelAcknowledge          *s25.HandoverCancelAcknowledge
	bodyERABSetupResponse                  *s46.ERABSetupResponse
	bodyERABModifyResponse                 *s46.ERABModifyResponse
	bodyERABReleaseResponse                *s46.ERABReleaseResponse
	bodyInitialContextSetupResponse        *s40.InitialContextSetupResponse
	bodyResetAcknowledge                   *s44.ResetAcknowledge
	bodyS1SetupResponse                    *s43.S1SetupResponse
	bodyUEContextModificationResponse      *s36.UEContextModificationResponse
	bodyUEContextReleaseComplete           *s46.UEContextReleaseComplete
	bodyENBConfigurationUpdateAcknowledge  *s24.ENBConfigurationUpdateAcknowledge
	bodyMMEConfigurationUpdateAcknowledge  *s25.MMEConfigurationUpdateAcknowledge
	bodyWriteReplaceWarningResponse        *WriteReplaceWarningResponse
	bodyKillResponse                       *s33.KillResponse
	bodyUERadioCapabilityMatchResponse     *s37.UERadioCapabilityMatchResponse
	bodyERABModificationConfirm            *s39.ERABModificationConfirm
	bodyUEContextModificationConfirm       *s36.UEContextModificationConfirm
	bodyUEContextSuspendResponse           *s36.UEContextSuspendResponse
	bodyUEContextResumeResponse            *s38.UEContextResumeResponse
	bodyUERadioCapabilityIDMappingResponse *s36.UERadioCapabilityIDMappingResponse
	bodyS1RemovalResponse                  *s26.S1RemovalResponse
}

// Opaque returns the retained opaque open value of SuccessfulValue and reports whether the opaque alternative is selected.
func (v *SuccessfulValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}

// AsHandoverCommand returns the selected HandoverCommand value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsHandoverCommand() (*s40.HandoverCommand, bool) {
	if v == nil || v.code != s00.ProcedureCode(0) || v.bodyHandoverCommand == nil {
		return nil, false
	}
	return v.bodyHandoverCommand, true
}

// AsHandoverRequestAcknowledge returns the selected HandoverRequestAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsHandoverRequestAcknowledge() (*s39.HandoverRequestAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(1) || v.bodyHandoverRequestAcknowledge == nil {
		return nil, false
	}
	return v.bodyHandoverRequestAcknowledge, true
}

// AsPathSwitchRequestAcknowledge returns the selected PathSwitchRequestAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsPathSwitchRequestAcknowledge() (*s47.PathSwitchRequestAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(3) || v.bodyPathSwitchRequestAcknowledge == nil {
		return nil, false
	}
	return v.bodyPathSwitchRequestAcknowledge, true
}

// AsHandoverCancelAcknowledge returns the selected HandoverCancelAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsHandoverCancelAcknowledge() (*s25.HandoverCancelAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(4) || v.bodyHandoverCancelAcknowledge == nil {
		return nil, false
	}
	return v.bodyHandoverCancelAcknowledge, true
}

// AsERABSetupResponse returns the selected ERABSetupResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsERABSetupResponse() (*s46.ERABSetupResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(5) || v.bodyERABSetupResponse == nil {
		return nil, false
	}
	return v.bodyERABSetupResponse, true
}

// AsERABModifyResponse returns the selected ERABModifyResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsERABModifyResponse() (*s46.ERABModifyResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(6) || v.bodyERABModifyResponse == nil {
		return nil, false
	}
	return v.bodyERABModifyResponse, true
}

// AsERABReleaseResponse returns the selected ERABReleaseResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsERABReleaseResponse() (*s46.ERABReleaseResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(7) || v.bodyERABReleaseResponse == nil {
		return nil, false
	}
	return v.bodyERABReleaseResponse, true
}

// AsInitialContextSetupResponse returns the selected InitialContextSetupResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsInitialContextSetupResponse() (*s40.InitialContextSetupResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(9) || v.bodyInitialContextSetupResponse == nil {
		return nil, false
	}
	return v.bodyInitialContextSetupResponse, true
}

// AsResetAcknowledge returns the selected ResetAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsResetAcknowledge() (*s44.ResetAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(14) || v.bodyResetAcknowledge == nil {
		return nil, false
	}
	return v.bodyResetAcknowledge, true
}

// AsS1SetupResponse returns the selected S1SetupResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsS1SetupResponse() (*s43.S1SetupResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(17) || v.bodyS1SetupResponse == nil {
		return nil, false
	}
	return v.bodyS1SetupResponse, true
}

// AsUEContextModificationResponse returns the selected UEContextModificationResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUEContextModificationResponse() (*s36.UEContextModificationResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(21) || v.bodyUEContextModificationResponse == nil {
		return nil, false
	}
	return v.bodyUEContextModificationResponse, true
}

// AsUEContextReleaseComplete returns the selected UEContextReleaseComplete value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUEContextReleaseComplete() (*s46.UEContextReleaseComplete, bool) {
	if v == nil || v.code != s00.ProcedureCode(23) || v.bodyUEContextReleaseComplete == nil {
		return nil, false
	}
	return v.bodyUEContextReleaseComplete, true
}

// AsENBConfigurationUpdateAcknowledge returns the selected ENBConfigurationUpdateAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsENBConfigurationUpdateAcknowledge() (*s24.ENBConfigurationUpdateAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(29) || v.bodyENBConfigurationUpdateAcknowledge == nil {
		return nil, false
	}
	return v.bodyENBConfigurationUpdateAcknowledge, true
}

// AsMMEConfigurationUpdateAcknowledge returns the selected MMEConfigurationUpdateAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsMMEConfigurationUpdateAcknowledge() (*s25.MMEConfigurationUpdateAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(30) || v.bodyMMEConfigurationUpdateAcknowledge == nil {
		return nil, false
	}
	return v.bodyMMEConfigurationUpdateAcknowledge, true
}

// AsWriteReplaceWarningResponse returns the selected WriteReplaceWarningResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsWriteReplaceWarningResponse() (*WriteReplaceWarningResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(36) || v.bodyWriteReplaceWarningResponse == nil {
		return nil, false
	}
	return v.bodyWriteReplaceWarningResponse, true
}

// AsKillResponse returns the selected KillResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsKillResponse() (*s33.KillResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(43) || v.bodyKillResponse == nil {
		return nil, false
	}
	return v.bodyKillResponse, true
}

// AsUERadioCapabilityMatchResponse returns the selected UERadioCapabilityMatchResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUERadioCapabilityMatchResponse() (*s37.UERadioCapabilityMatchResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(48) || v.bodyUERadioCapabilityMatchResponse == nil {
		return nil, false
	}
	return v.bodyUERadioCapabilityMatchResponse, true
}

// AsERABModificationConfirm returns the selected ERABModificationConfirm value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsERABModificationConfirm() (*s39.ERABModificationConfirm, bool) {
	if v == nil || v.code != s00.ProcedureCode(50) || v.bodyERABModificationConfirm == nil {
		return nil, false
	}
	return v.bodyERABModificationConfirm, true
}

// AsUEContextModificationConfirm returns the selected UEContextModificationConfirm value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUEContextModificationConfirm() (*s36.UEContextModificationConfirm, bool) {
	if v == nil || v.code != s00.ProcedureCode(53) || v.bodyUEContextModificationConfirm == nil {
		return nil, false
	}
	return v.bodyUEContextModificationConfirm, true
}

// AsUEContextSuspendResponse returns the selected UEContextSuspendResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUEContextSuspendResponse() (*s36.UEContextSuspendResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(55) || v.bodyUEContextSuspendResponse == nil {
		return nil, false
	}
	return v.bodyUEContextSuspendResponse, true
}

// AsUEContextResumeResponse returns the selected UEContextResumeResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUEContextResumeResponse() (*s38.UEContextResumeResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(56) || v.bodyUEContextResumeResponse == nil {
		return nil, false
	}
	return v.bodyUEContextResumeResponse, true
}

// AsUERadioCapabilityIDMappingResponse returns the selected UERadioCapabilityIDMappingResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUERadioCapabilityIDMappingResponse() (*s36.UERadioCapabilityIDMappingResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(63) || v.bodyUERadioCapabilityIDMappingResponse == nil {
		return nil, false
	}
	return v.bodyUERadioCapabilityIDMappingResponse, true
}

// AsS1RemovalResponse returns the selected S1RemovalResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsS1RemovalResponse() (*s26.S1RemovalResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(67) || v.bodyS1RemovalResponse == nil {
		return nil, false
	}
	return v.bodyS1RemovalResponse, true
}
func BridgeDecodeSuccessfulValue(code s00.ProcedureCode, raw aper.OpaqueOpenType) (SuccessfulValue, error) {
	v := SuccessfulValue{code: code}
	switch code {
	case s00.ProcedureCode(0):
		var body s40.HandoverCommand
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s40.BridgeHandoverCommandMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.HandoverCommand:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverCommand")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s40.BridgeHandoverCommandFieldPerPadding(&body) = padding
		*s40.BridgeHandoverCommandFieldReceived(&body) = true
		raw.RetainContents(s40.BridgeHandoverCommandFieldReceivedBytes(&body))
		*s40.BridgeHandoverCommandFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyHandoverCommand = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(1):
		var body s39.HandoverRequestAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s39.BridgeHandoverRequestAcknowledgeMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.HandoverRequestAcknowledge:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverRequestAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s39.BridgeHandoverRequestAcknowledgeFieldPerPadding(&body) = padding
		*s39.BridgeHandoverRequestAcknowledgeFieldReceived(&body) = true
		raw.RetainContents(s39.BridgeHandoverRequestAcknowledgeFieldReceivedBytes(&body))
		*s39.BridgeHandoverRequestAcknowledgeFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyHandoverRequestAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(3):
		var body s47.PathSwitchRequestAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s47.BridgePathSwitchRequestAcknowledgeMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.PathSwitchRequestAcknowledge:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PathSwitchRequestAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s47.BridgePathSwitchRequestAcknowledgeFieldPerPadding(&body) = padding
		*s47.BridgePathSwitchRequestAcknowledgeFieldReceived(&body) = true
		raw.RetainContents(s47.BridgePathSwitchRequestAcknowledgeFieldReceivedBytes(&body))
		*s47.BridgePathSwitchRequestAcknowledgeFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyPathSwitchRequestAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(4):
		var body s25.HandoverCancelAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s25.BridgeHandoverCancelAcknowledgeMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.HandoverCancelAcknowledge:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverCancelAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s25.BridgeHandoverCancelAcknowledgeFieldPerPadding(&body) = padding
		*s25.BridgeHandoverCancelAcknowledgeFieldReceived(&body) = true
		raw.RetainContents(s25.BridgeHandoverCancelAcknowledgeFieldReceivedBytes(&body))
		*s25.BridgeHandoverCancelAcknowledgeFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyHandoverCancelAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(5):
		var body s46.ERABSetupResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s46.BridgeERABSetupResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ERABSetupResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABSetupResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s46.BridgeERABSetupResponseFieldPerPadding(&body) = padding
		*s46.BridgeERABSetupResponseFieldReceived(&body) = true
		raw.RetainContents(s46.BridgeERABSetupResponseFieldReceivedBytes(&body))
		*s46.BridgeERABSetupResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyERABSetupResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(6):
		var body s46.ERABModifyResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s46.BridgeERABModifyResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ERABModifyResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABModifyResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s46.BridgeERABModifyResponseFieldPerPadding(&body) = padding
		*s46.BridgeERABModifyResponseFieldReceived(&body) = true
		raw.RetainContents(s46.BridgeERABModifyResponseFieldReceivedBytes(&body))
		*s46.BridgeERABModifyResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyERABModifyResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(7):
		var body s46.ERABReleaseResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s46.BridgeERABReleaseResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ERABReleaseResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABReleaseResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s46.BridgeERABReleaseResponseFieldPerPadding(&body) = padding
		*s46.BridgeERABReleaseResponseFieldReceived(&body) = true
		raw.RetainContents(s46.BridgeERABReleaseResponseFieldReceivedBytes(&body))
		*s46.BridgeERABReleaseResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyERABReleaseResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(9):
		var body s40.InitialContextSetupResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s40.BridgeInitialContextSetupResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.InitialContextSetupResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "InitialContextSetupResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s40.BridgeInitialContextSetupResponseFieldPerPadding(&body) = padding
		*s40.BridgeInitialContextSetupResponseFieldReceived(&body) = true
		raw.RetainContents(s40.BridgeInitialContextSetupResponseFieldReceivedBytes(&body))
		*s40.BridgeInitialContextSetupResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyInitialContextSetupResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(14):
		var body s44.ResetAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s44.BridgeResetAcknowledgeMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ResetAcknowledge:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ResetAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s44.BridgeResetAcknowledgeFieldPerPadding(&body) = padding
		*s44.BridgeResetAcknowledgeFieldReceived(&body) = true
		raw.RetainContents(s44.BridgeResetAcknowledgeFieldReceivedBytes(&body))
		*s44.BridgeResetAcknowledgeFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyResetAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(17):
		var body s43.S1SetupResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s43.BridgeS1SetupResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.S1SetupResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "S1SetupResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s43.BridgeS1SetupResponseFieldPerPadding(&body) = padding
		*s43.BridgeS1SetupResponseFieldReceived(&body) = true
		raw.RetainContents(s43.BridgeS1SetupResponseFieldReceivedBytes(&body))
		*s43.BridgeS1SetupResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyS1SetupResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(21):
		var body s36.UEContextModificationResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s36.BridgeUEContextModificationResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UEContextModificationResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextModificationResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s36.BridgeUEContextModificationResponseFieldPerPadding(&body) = padding
		*s36.BridgeUEContextModificationResponseFieldReceived(&body) = true
		raw.RetainContents(s36.BridgeUEContextModificationResponseFieldReceivedBytes(&body))
		*s36.BridgeUEContextModificationResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextModificationResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(23):
		var body s46.UEContextReleaseComplete
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s46.BridgeUEContextReleaseCompleteMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UEContextReleaseComplete:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextReleaseComplete")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s46.BridgeUEContextReleaseCompleteFieldPerPadding(&body) = padding
		*s46.BridgeUEContextReleaseCompleteFieldReceived(&body) = true
		raw.RetainContents(s46.BridgeUEContextReleaseCompleteFieldReceivedBytes(&body))
		*s46.BridgeUEContextReleaseCompleteFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextReleaseComplete = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(29):
		var body s24.ENBConfigurationUpdateAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s24.BridgeENBConfigurationUpdateAcknowledgeMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ENBConfigurationUpdateAcknowledge:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBConfigurationUpdateAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s24.BridgeENBConfigurationUpdateAcknowledgeFieldPerPadding(&body) = padding
		*s24.BridgeENBConfigurationUpdateAcknowledgeFieldReceived(&body) = true
		raw.RetainContents(s24.BridgeENBConfigurationUpdateAcknowledgeFieldReceivedBytes(&body))
		*s24.BridgeENBConfigurationUpdateAcknowledgeFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyENBConfigurationUpdateAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(30):
		var body s25.MMEConfigurationUpdateAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s25.BridgeMMEConfigurationUpdateAcknowledgeMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.MMEConfigurationUpdateAcknowledge:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "MMEConfigurationUpdateAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s25.BridgeMMEConfigurationUpdateAcknowledgeFieldPerPadding(&body) = padding
		*s25.BridgeMMEConfigurationUpdateAcknowledgeFieldReceived(&body) = true
		raw.RetainContents(s25.BridgeMMEConfigurationUpdateAcknowledgeFieldReceivedBytes(&body))
		*s25.BridgeMMEConfigurationUpdateAcknowledgeFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyMMEConfigurationUpdateAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(36):
		var body WriteReplaceWarningResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := body.unmarshalAPERFrom(child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.WriteReplaceWarningResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "WriteReplaceWarningResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.ContentLocation()
		v.bodyWriteReplaceWarningResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(43):
		var body s33.KillResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s33.BridgeKillResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.KillResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "KillResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s33.BridgeKillResponseFieldPerPadding(&body) = padding
		*s33.BridgeKillResponseFieldReceived(&body) = true
		raw.RetainContents(s33.BridgeKillResponseFieldReceivedBytes(&body))
		*s33.BridgeKillResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyKillResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(48):
		var body s37.UERadioCapabilityMatchResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s37.BridgeUERadioCapabilityMatchResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UERadioCapabilityMatchResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UERadioCapabilityMatchResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s37.BridgeUERadioCapabilityMatchResponseFieldPerPadding(&body) = padding
		*s37.BridgeUERadioCapabilityMatchResponseFieldReceived(&body) = true
		raw.RetainContents(s37.BridgeUERadioCapabilityMatchResponseFieldReceivedBytes(&body))
		*s37.BridgeUERadioCapabilityMatchResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUERadioCapabilityMatchResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(50):
		var body s39.ERABModificationConfirm
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s39.BridgeERABModificationConfirmMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ERABModificationConfirm:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABModificationConfirm")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s39.BridgeERABModificationConfirmFieldPerPadding(&body) = padding
		*s39.BridgeERABModificationConfirmFieldReceived(&body) = true
		raw.RetainContents(s39.BridgeERABModificationConfirmFieldReceivedBytes(&body))
		*s39.BridgeERABModificationConfirmFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyERABModificationConfirm = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(53):
		var body s36.UEContextModificationConfirm
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s36.BridgeUEContextModificationConfirmMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UEContextModificationConfirm:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextModificationConfirm")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s36.BridgeUEContextModificationConfirmFieldPerPadding(&body) = padding
		*s36.BridgeUEContextModificationConfirmFieldReceived(&body) = true
		raw.RetainContents(s36.BridgeUEContextModificationConfirmFieldReceivedBytes(&body))
		*s36.BridgeUEContextModificationConfirmFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextModificationConfirm = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(55):
		var body s36.UEContextSuspendResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s36.BridgeUEContextSuspendResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UEContextSuspendResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextSuspendResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s36.BridgeUEContextSuspendResponseFieldPerPadding(&body) = padding
		*s36.BridgeUEContextSuspendResponseFieldReceived(&body) = true
		raw.RetainContents(s36.BridgeUEContextSuspendResponseFieldReceivedBytes(&body))
		*s36.BridgeUEContextSuspendResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextSuspendResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(56):
		var body s38.UEContextResumeResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s38.BridgeUEContextResumeResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UEContextResumeResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextResumeResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s38.BridgeUEContextResumeResponseFieldPerPadding(&body) = padding
		*s38.BridgeUEContextResumeResponseFieldReceived(&body) = true
		raw.RetainContents(s38.BridgeUEContextResumeResponseFieldReceivedBytes(&body))
		*s38.BridgeUEContextResumeResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextResumeResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(63):
		var body s36.UERadioCapabilityIDMappingResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s36.BridgeUERadioCapabilityIDMappingResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UERadioCapabilityIDMappingResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UERadioCapabilityIDMappingResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s36.BridgeUERadioCapabilityIDMappingResponseFieldPerPadding(&body) = padding
		*s36.BridgeUERadioCapabilityIDMappingResponseFieldReceived(&body) = true
		raw.RetainContents(s36.BridgeUERadioCapabilityIDMappingResponseFieldReceivedBytes(&body))
		*s36.BridgeUERadioCapabilityIDMappingResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUERadioCapabilityIDMappingResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(67):
		var body s26.S1RemovalResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s26.BridgeS1RemovalResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.S1RemovalResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "S1RemovalResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s26.BridgeS1RemovalResponseFieldPerPadding(&body) = padding
		*s26.BridgeS1RemovalResponseFieldReceived(&body) = true
		raw.RetainContents(s26.BridgeS1RemovalResponseFieldReceivedBytes(&body))
		*s26.BridgeS1RemovalResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyS1RemovalResponse = &body
		raw.RetainContents(&v.received)
	default:
		if err := raw.Observe(aper.UnknownProcedure); err != nil {
			return v, err
		}
		v.opaque = raw.Detached()
		v.isOpaque = true
	}
	return v, nil
}
func (v SuccessfulValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v SuccessfulValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if budget == nil {
		var err error
		budget, err = aper.EncodeBudget()
		if err != nil {
			return nil, err
		}
	}
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.code {
	case s00.ProcedureCode(0):
		if v.bodyHandoverCommand == nil {
			return nil, fmt.Errorf("%s value: missing HandoverCommand", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s40.BridgeHandoverCommandMethodMarshalAPERBudget(v.bodyHandoverCommand, budget, fresh)
	case s00.ProcedureCode(1):
		if v.bodyHandoverRequestAcknowledge == nil {
			return nil, fmt.Errorf("%s value: missing HandoverRequestAcknowledge", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s39.BridgeHandoverRequestAcknowledgeMethodMarshalAPERBudget(v.bodyHandoverRequestAcknowledge, budget, fresh)
	case s00.ProcedureCode(3):
		if v.bodyPathSwitchRequestAcknowledge == nil {
			return nil, fmt.Errorf("%s value: missing PathSwitchRequestAcknowledge", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s47.BridgePathSwitchRequestAcknowledgeMethodMarshalAPERBudget(v.bodyPathSwitchRequestAcknowledge, budget, fresh)
	case s00.ProcedureCode(4):
		if v.bodyHandoverCancelAcknowledge == nil {
			return nil, fmt.Errorf("%s value: missing HandoverCancelAcknowledge", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s25.BridgeHandoverCancelAcknowledgeMethodMarshalAPERBudget(v.bodyHandoverCancelAcknowledge, budget, fresh)
	case s00.ProcedureCode(5):
		if v.bodyERABSetupResponse == nil {
			return nil, fmt.Errorf("%s value: missing ERABSetupResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s46.BridgeERABSetupResponseMethodMarshalAPERBudget(v.bodyERABSetupResponse, budget, fresh)
	case s00.ProcedureCode(6):
		if v.bodyERABModifyResponse == nil {
			return nil, fmt.Errorf("%s value: missing ERABModifyResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s46.BridgeERABModifyResponseMethodMarshalAPERBudget(v.bodyERABModifyResponse, budget, fresh)
	case s00.ProcedureCode(7):
		if v.bodyERABReleaseResponse == nil {
			return nil, fmt.Errorf("%s value: missing ERABReleaseResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s46.BridgeERABReleaseResponseMethodMarshalAPERBudget(v.bodyERABReleaseResponse, budget, fresh)
	case s00.ProcedureCode(9):
		if v.bodyInitialContextSetupResponse == nil {
			return nil, fmt.Errorf("%s value: missing InitialContextSetupResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s40.BridgeInitialContextSetupResponseMethodMarshalAPERBudget(v.bodyInitialContextSetupResponse, budget, fresh)
	case s00.ProcedureCode(14):
		if v.bodyResetAcknowledge == nil {
			return nil, fmt.Errorf("%s value: missing ResetAcknowledge", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s44.BridgeResetAcknowledgeMethodMarshalAPERBudget(v.bodyResetAcknowledge, budget, fresh)
	case s00.ProcedureCode(17):
		if v.bodyS1SetupResponse == nil {
			return nil, fmt.Errorf("%s value: missing S1SetupResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s43.BridgeS1SetupResponseMethodMarshalAPERBudget(v.bodyS1SetupResponse, budget, fresh)
	case s00.ProcedureCode(21):
		if v.bodyUEContextModificationResponse == nil {
			return nil, fmt.Errorf("%s value: missing UEContextModificationResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s36.BridgeUEContextModificationResponseMethodMarshalAPERBudget(v.bodyUEContextModificationResponse, budget, fresh)
	case s00.ProcedureCode(23):
		if v.bodyUEContextReleaseComplete == nil {
			return nil, fmt.Errorf("%s value: missing UEContextReleaseComplete", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s46.BridgeUEContextReleaseCompleteMethodMarshalAPERBudget(v.bodyUEContextReleaseComplete, budget, fresh)
	case s00.ProcedureCode(29):
		if v.bodyENBConfigurationUpdateAcknowledge == nil {
			return nil, fmt.Errorf("%s value: missing ENBConfigurationUpdateAcknowledge", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s24.BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(v.bodyENBConfigurationUpdateAcknowledge, budget, fresh)
	case s00.ProcedureCode(30):
		if v.bodyMMEConfigurationUpdateAcknowledge == nil {
			return nil, fmt.Errorf("%s value: missing MMEConfigurationUpdateAcknowledge", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s25.BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(v.bodyMMEConfigurationUpdateAcknowledge, budget, fresh)
	case s00.ProcedureCode(36):
		if v.bodyWriteReplaceWarningResponse == nil {
			return nil, fmt.Errorf("%s value: missing WriteReplaceWarningResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return v.bodyWriteReplaceWarningResponse.marshalAPERBudget(budget, fresh)
	case s00.ProcedureCode(43):
		if v.bodyKillResponse == nil {
			return nil, fmt.Errorf("%s value: missing KillResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s33.BridgeKillResponseMethodMarshalAPERBudget(v.bodyKillResponse, budget, fresh)
	case s00.ProcedureCode(48):
		if v.bodyUERadioCapabilityMatchResponse == nil {
			return nil, fmt.Errorf("%s value: missing UERadioCapabilityMatchResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s37.BridgeUERadioCapabilityMatchResponseMethodMarshalAPERBudget(v.bodyUERadioCapabilityMatchResponse, budget, fresh)
	case s00.ProcedureCode(50):
		if v.bodyERABModificationConfirm == nil {
			return nil, fmt.Errorf("%s value: missing ERABModificationConfirm", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s39.BridgeERABModificationConfirmMethodMarshalAPERBudget(v.bodyERABModificationConfirm, budget, fresh)
	case s00.ProcedureCode(53):
		if v.bodyUEContextModificationConfirm == nil {
			return nil, fmt.Errorf("%s value: missing UEContextModificationConfirm", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s36.BridgeUEContextModificationConfirmMethodMarshalAPERBudget(v.bodyUEContextModificationConfirm, budget, fresh)
	case s00.ProcedureCode(55):
		if v.bodyUEContextSuspendResponse == nil {
			return nil, fmt.Errorf("%s value: missing UEContextSuspendResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s36.BridgeUEContextSuspendResponseMethodMarshalAPERBudget(v.bodyUEContextSuspendResponse, budget, fresh)
	case s00.ProcedureCode(56):
		if v.bodyUEContextResumeResponse == nil {
			return nil, fmt.Errorf("%s value: missing UEContextResumeResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s38.BridgeUEContextResumeResponseMethodMarshalAPERBudget(v.bodyUEContextResumeResponse, budget, fresh)
	case s00.ProcedureCode(63):
		if v.bodyUERadioCapabilityIDMappingResponse == nil {
			return nil, fmt.Errorf("%s value: missing UERadioCapabilityIDMappingResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s36.BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERBudget(v.bodyUERadioCapabilityIDMappingResponse, budget, fresh)
	case s00.ProcedureCode(67):
		if v.bodyS1RemovalResponse == nil {
			return nil, fmt.Errorf("%s value: missing S1RemovalResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s26.BridgeS1RemovalResponseMethodMarshalAPERBudget(v.bodyS1RemovalResponse, budget, fresh)
	default:
		return nil, fmt.Errorf("%s value: unknown code %d without opaque content", "Successful", v.code)
	}
}
func NewOpaqueSuccessfulOutcome(code s00.ProcedureCode, criticality s00.Criticality, data []byte) (SuccessfulOutcome, error) {
	switch code {
	case s00.ProcedureCode(0):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-HandoverPreparation requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(1):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-HandoverResourceAllocation requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(3):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-PathSwitchRequest requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(4):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-HandoverCancel requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(5):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-E-RABSetup requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(6):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-E-RABModify requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(7):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-E-RABRelease requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(9):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-InitialContextSetup requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(14):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-Reset requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(17):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-S1Setup requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(21):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-UEContextModification requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(23):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-UEContextRelease requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(29):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-ENBConfigurationUpdate requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(30):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-MMEConfigurationUpdate requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(36):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-WriteReplaceWarning requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(43):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-Kill requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(48):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-UERadioCapabilityMatch requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(50):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-E-RABModificationIndication requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(53):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-UEContextModificationIndication requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(55):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-UEContextSuspend requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(56):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-UEContextResume requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(63):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-UERadioCapabilityIDMapping requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(67):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-S1Removal requires its typed binding"), "OpaqueSuccessfulOutcome")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "OpaqueSuccessfulOutcome")
	}
	opaque, err := aper.BuildOpaqueOpenType(data, budget)
	if err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "OpaqueSuccessfulOutcome")
	}
	message := SuccessfulOutcome{ProcedureCode: code, Criticality: criticality, Value: SuccessfulValue{code: code, opaque: opaque, isOpaque: true}}
	if _, err := message.marshalAPERBudget(budget, false); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "OpaqueSuccessfulOutcome")
	}
	return message, aper.OperationError(nil, "OpaqueSuccessfulOutcome")
}
func BridgeCaptureS1APSONConfigurationTransferExtIEsValue(v *SONConfigurationTransferExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(152):
			{
				f := s.Begin()
				s.Bool(v.rowX2TNLConfigurationInfo == nil)
				if v.rowX2TNLConfigurationInfo != nil {
					BridgeCaptureS1APX2TNLConfigurationInfo(v.rowX2TNLConfigurationInfo, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(209):
			{
				f := s.Begin()
				s.Bool(v.rowSynchronisationInformation == nil)
				if v.rowSynchronisationInformation != nil {
					s31.BridgeCaptureS1APSynchronisationInformation(v.rowSynchronisationInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(356):
			{
				f := s.Begin()
				s.Bool(v.rowRequestedTNLInfo == nil)
				if v.rowRequestedTNLInfo != nil {
					s26.BridgeCaptureS1APRequestedTNLInfo(v.rowRequestedTNLInfo, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SONConfigurationTransferExtIEsValue) captureSemantics(s aper.SemanticCapture) SONConfigurationTransferExtIEsValue {
	BridgeCaptureS1APSONConfigurationTransferExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APSONConfigurationTransferExtIEsValue(v *SONConfigurationTransferExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(152):
			{
				f := s.Begin()
				s.Bool(v.rowX2TNLConfigurationInfo == nil)
				if v.rowX2TNLConfigurationInfo != nil {
					BridgeCompareS1APX2TNLConfigurationInfo(v.rowX2TNLConfigurationInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(209):
			{
				f := s.Begin()
				s.Bool(v.rowSynchronisationInformation == nil)
				if v.rowSynchronisationInformation != nil {
					s31.BridgeCompareS1APSynchronisationInformation(v.rowSynchronisationInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(356):
			{
				f := s.Begin()
				s.Bool(v.rowRequestedTNLInfo == nil)
				if v.rowRequestedTNLInfo != nil {
					s26.BridgeCompareS1APRequestedTNLInfo(v.rowRequestedTNLInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SONConfigurationTransferExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APSONConfigurationTransferExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APSONInformationReply(v *SONInformationReply, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.X2TNLConfigurationInfo == nil)
		if v.X2TNLConfigurationInfo != nil {
			BridgeCaptureS1APX2TNLConfigurationInfo(v.X2TNLConfigurationInfo, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s34.BridgeSONInformationReplyExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSONInformationReply(v *SONInformationReply, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Bool(v.X2TNLConfigurationInfo == nil)
		if v.X2TNLConfigurationInfo != nil {
			BridgeCompareS1APX2TNLConfigurationInfo(v.X2TNLConfigurationInfo, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s34.BridgeSONInformationReplyExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSuccessfulOutcome(v *SuccessfulOutcome, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProcedureCode(&v.ProcedureCode, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	BridgeCaptureS1APSuccessfulValue(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSuccessfulOutcome(v *SuccessfulOutcome, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProcedureCode(&v.ProcedureCode, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	BridgeCompareS1APSuccessfulValue(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSuccessfulValue(v *SuccessfulValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProcedureCode(&v.code, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.code {
		case s00.ProcedureCode(0):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverCommand == nil)
				if v.bodyHandoverCommand != nil {
					s40.BridgeCaptureS1APHandoverCommand(v.bodyHandoverCommand, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(1):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverRequestAcknowledge == nil)
				if v.bodyHandoverRequestAcknowledge != nil {
					s39.BridgeCaptureS1APHandoverRequestAcknowledge(v.bodyHandoverRequestAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(3):
			{
				f := s.Begin()
				s.Bool(v.bodyPathSwitchRequestAcknowledge == nil)
				if v.bodyPathSwitchRequestAcknowledge != nil {
					s47.BridgeCaptureS1APPathSwitchRequestAcknowledge(v.bodyPathSwitchRequestAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(4):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverCancelAcknowledge == nil)
				if v.bodyHandoverCancelAcknowledge != nil {
					s25.BridgeCaptureS1APHandoverCancelAcknowledge(v.bodyHandoverCancelAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(5):
			{
				f := s.Begin()
				s.Bool(v.bodyERABSetupResponse == nil)
				if v.bodyERABSetupResponse != nil {
					s46.BridgeCaptureS1APERABSetupResponse(v.bodyERABSetupResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyERABModifyResponse == nil)
				if v.bodyERABModifyResponse != nil {
					s46.BridgeCaptureS1APERABModifyResponse(v.bodyERABModifyResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyERABReleaseResponse == nil)
				if v.bodyERABReleaseResponse != nil {
					s46.BridgeCaptureS1APERABReleaseResponse(v.bodyERABReleaseResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyInitialContextSetupResponse == nil)
				if v.bodyInitialContextSetupResponse != nil {
					s40.BridgeCaptureS1APInitialContextSetupResponse(v.bodyInitialContextSetupResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(14):
			{
				f := s.Begin()
				s.Bool(v.bodyResetAcknowledge == nil)
				if v.bodyResetAcknowledge != nil {
					s44.BridgeCaptureS1APResetAcknowledge(v.bodyResetAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(17):
			{
				f := s.Begin()
				s.Bool(v.bodyS1SetupResponse == nil)
				if v.bodyS1SetupResponse != nil {
					s43.BridgeCaptureS1APS1SetupResponse(v.bodyS1SetupResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationResponse == nil)
				if v.bodyUEContextModificationResponse != nil {
					s36.BridgeCaptureS1APUEContextModificationResponse(v.bodyUEContextModificationResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(23):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextReleaseComplete == nil)
				if v.bodyUEContextReleaseComplete != nil {
					s46.BridgeCaptureS1APUEContextReleaseComplete(v.bodyUEContextReleaseComplete, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(29):
			{
				f := s.Begin()
				s.Bool(v.bodyENBConfigurationUpdateAcknowledge == nil)
				if v.bodyENBConfigurationUpdateAcknowledge != nil {
					s24.BridgeCaptureS1APENBConfigurationUpdateAcknowledge(v.bodyENBConfigurationUpdateAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(30):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEConfigurationUpdateAcknowledge == nil)
				if v.bodyMMEConfigurationUpdateAcknowledge != nil {
					s25.BridgeCaptureS1APMMEConfigurationUpdateAcknowledge(v.bodyMMEConfigurationUpdateAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(36):
			{
				f := s.Begin()
				s.Bool(v.bodyWriteReplaceWarningResponse == nil)
				if v.bodyWriteReplaceWarningResponse != nil {
					BridgeCaptureS1APWriteReplaceWarningResponse(v.bodyWriteReplaceWarningResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(43):
			{
				f := s.Begin()
				s.Bool(v.bodyKillResponse == nil)
				if v.bodyKillResponse != nil {
					s33.BridgeCaptureS1APKillResponse(v.bodyKillResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(48):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityMatchResponse == nil)
				if v.bodyUERadioCapabilityMatchResponse != nil {
					s37.BridgeCaptureS1APUERadioCapabilityMatchResponse(v.bodyUERadioCapabilityMatchResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(50):
			{
				f := s.Begin()
				s.Bool(v.bodyERABModificationConfirm == nil)
				if v.bodyERABModificationConfirm != nil {
					s39.BridgeCaptureS1APERABModificationConfirm(v.bodyERABModificationConfirm, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(53):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationConfirm == nil)
				if v.bodyUEContextModificationConfirm != nil {
					s36.BridgeCaptureS1APUEContextModificationConfirm(v.bodyUEContextModificationConfirm, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(55):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextSuspendResponse == nil)
				if v.bodyUEContextSuspendResponse != nil {
					s36.BridgeCaptureS1APUEContextSuspendResponse(v.bodyUEContextSuspendResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(56):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextResumeResponse == nil)
				if v.bodyUEContextResumeResponse != nil {
					s38.BridgeCaptureS1APUEContextResumeResponse(v.bodyUEContextResumeResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(63):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityIDMappingResponse == nil)
				if v.bodyUERadioCapabilityIDMappingResponse != nil {
					s36.BridgeCaptureS1APUERadioCapabilityIDMappingResponse(v.bodyUERadioCapabilityIDMappingResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(67):
			{
				f := s.Begin()
				s.Bool(v.bodyS1RemovalResponse == nil)
				if v.bodyS1RemovalResponse != nil {
					s26.BridgeCaptureS1APS1RemovalResponse(v.bodyS1RemovalResponse, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SuccessfulValue) captureSemantics(s aper.SemanticCapture) SuccessfulValue {
	BridgeCaptureS1APSuccessfulValue(&v, &s)
	return v
}
func BridgeCompareS1APSuccessfulValue(v *SuccessfulValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProcedureCode(&v.code, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.code {
		case s00.ProcedureCode(0):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverCommand == nil)
				if v.bodyHandoverCommand != nil {
					s40.BridgeCompareS1APHandoverCommand(v.bodyHandoverCommand, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(1):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverRequestAcknowledge == nil)
				if v.bodyHandoverRequestAcknowledge != nil {
					s39.BridgeCompareS1APHandoverRequestAcknowledge(v.bodyHandoverRequestAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(3):
			{
				f := s.Begin()
				s.Bool(v.bodyPathSwitchRequestAcknowledge == nil)
				if v.bodyPathSwitchRequestAcknowledge != nil {
					s47.BridgeCompareS1APPathSwitchRequestAcknowledge(v.bodyPathSwitchRequestAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(4):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverCancelAcknowledge == nil)
				if v.bodyHandoverCancelAcknowledge != nil {
					s25.BridgeCompareS1APHandoverCancelAcknowledge(v.bodyHandoverCancelAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(5):
			{
				f := s.Begin()
				s.Bool(v.bodyERABSetupResponse == nil)
				if v.bodyERABSetupResponse != nil {
					s46.BridgeCompareS1APERABSetupResponse(v.bodyERABSetupResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyERABModifyResponse == nil)
				if v.bodyERABModifyResponse != nil {
					s46.BridgeCompareS1APERABModifyResponse(v.bodyERABModifyResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyERABReleaseResponse == nil)
				if v.bodyERABReleaseResponse != nil {
					s46.BridgeCompareS1APERABReleaseResponse(v.bodyERABReleaseResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyInitialContextSetupResponse == nil)
				if v.bodyInitialContextSetupResponse != nil {
					s40.BridgeCompareS1APInitialContextSetupResponse(v.bodyInitialContextSetupResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(14):
			{
				f := s.Begin()
				s.Bool(v.bodyResetAcknowledge == nil)
				if v.bodyResetAcknowledge != nil {
					s44.BridgeCompareS1APResetAcknowledge(v.bodyResetAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(17):
			{
				f := s.Begin()
				s.Bool(v.bodyS1SetupResponse == nil)
				if v.bodyS1SetupResponse != nil {
					s43.BridgeCompareS1APS1SetupResponse(v.bodyS1SetupResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationResponse == nil)
				if v.bodyUEContextModificationResponse != nil {
					s36.BridgeCompareS1APUEContextModificationResponse(v.bodyUEContextModificationResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(23):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextReleaseComplete == nil)
				if v.bodyUEContextReleaseComplete != nil {
					s46.BridgeCompareS1APUEContextReleaseComplete(v.bodyUEContextReleaseComplete, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(29):
			{
				f := s.Begin()
				s.Bool(v.bodyENBConfigurationUpdateAcknowledge == nil)
				if v.bodyENBConfigurationUpdateAcknowledge != nil {
					s24.BridgeCompareS1APENBConfigurationUpdateAcknowledge(v.bodyENBConfigurationUpdateAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(30):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEConfigurationUpdateAcknowledge == nil)
				if v.bodyMMEConfigurationUpdateAcknowledge != nil {
					s25.BridgeCompareS1APMMEConfigurationUpdateAcknowledge(v.bodyMMEConfigurationUpdateAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(36):
			{
				f := s.Begin()
				s.Bool(v.bodyWriteReplaceWarningResponse == nil)
				if v.bodyWriteReplaceWarningResponse != nil {
					BridgeCompareS1APWriteReplaceWarningResponse(v.bodyWriteReplaceWarningResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(43):
			{
				f := s.Begin()
				s.Bool(v.bodyKillResponse == nil)
				if v.bodyKillResponse != nil {
					s33.BridgeCompareS1APKillResponse(v.bodyKillResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(48):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityMatchResponse == nil)
				if v.bodyUERadioCapabilityMatchResponse != nil {
					s37.BridgeCompareS1APUERadioCapabilityMatchResponse(v.bodyUERadioCapabilityMatchResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(50):
			{
				f := s.Begin()
				s.Bool(v.bodyERABModificationConfirm == nil)
				if v.bodyERABModificationConfirm != nil {
					s39.BridgeCompareS1APERABModificationConfirm(v.bodyERABModificationConfirm, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(53):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationConfirm == nil)
				if v.bodyUEContextModificationConfirm != nil {
					s36.BridgeCompareS1APUEContextModificationConfirm(v.bodyUEContextModificationConfirm, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(55):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextSuspendResponse == nil)
				if v.bodyUEContextSuspendResponse != nil {
					s36.BridgeCompareS1APUEContextSuspendResponse(v.bodyUEContextSuspendResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(56):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextResumeResponse == nil)
				if v.bodyUEContextResumeResponse != nil {
					s38.BridgeCompareS1APUEContextResumeResponse(v.bodyUEContextResumeResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(63):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityIDMappingResponse == nil)
				if v.bodyUERadioCapabilityIDMappingResponse != nil {
					s36.BridgeCompareS1APUERadioCapabilityIDMappingResponse(v.bodyUERadioCapabilityIDMappingResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(67):
			{
				f := s.Begin()
				s.Bool(v.bodyS1RemovalResponse == nil)
				if v.bodyS1RemovalResponse != nil {
					s26.BridgeCompareS1APS1RemovalResponse(v.bodyS1RemovalResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v SuccessfulValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APSuccessfulValue(&v, &s)
	return s
}
func BridgeCaptureS1APWriteReplaceWarningRequest(v *WriteReplaceWarningRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APWriteReplaceWarningRequest(v *WriteReplaceWarningRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APWriteReplaceWarningResponse(v *WriteReplaceWarningResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APWriteReplaceWarningResponse(v *WriteReplaceWarningResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APX2TNLConfigurationInfo(v *X2TNLConfigurationInfo, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APENBX2TLAs(&v.ENBX2TransportLayerAddresses, s)
	s.Bool(v.IEExtensions == nil)
	BridgeX2TNLConfigurationInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APX2TNLConfigurationInfo(v *X2TNLConfigurationInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s07.BridgeCompareS1APENBX2TLAs(&v.ENBX2TransportLayerAddresses, s)
	s.Bool(v.IEExtensions == nil)
	BridgeX2TNLConfigurationInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}

// SONInformationReply represents the ASN.1 type SONInformationReply (SEQUENCE).
type SONInformationReply struct {
	replay                 aper.Snapshot
	stream                 aper.WireSpan
	received               bool
	withoutReplay          bool
	receivedAbsolute       bool
	receivedBytes          aper.WireSpan
	receivedLocation       aper.Location
	X2TNLConfigurationInfo *X2TNLConfigurationInfo                   `asn1:"tag:0,context,implicit,optional" json:"X2TNLConfigurationInfo,omitempty"`
	IEExtensions           s34.SONInformationReplyExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef      bool                                      `asn1:"-" json:"-"`
	extCount               int64                                     `asn1:"-" json:"-"`
	extPresent             []bool                                    `asn1:"-" json:"-"`
	extData                [][]byte                                  `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
}

// X2TNLConfigurationInfo represents the ASN.1 type X2TNLConfigurationInfo (SEQUENCE).
type X2TNLConfigurationInfo struct {
	replay                            aper.Snapshot
	stream                            aper.WireSpan
	received                          bool
	withoutReplay                     bool
	receivedAbsolute                  bool
	receivedBytes                     aper.WireSpan
	receivedLocation                  aper.Location
	ENBX2TransportLayerAddresses      s00.ENBX2TLAs                                `asn1:"tag:0,context,implicit"`
	eNBX2TransportLayerAddressesIndef bool                                         `asn1:"-" json:"-"`
	IEExtensions                      s38.X2TNLConfigurationInfoExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                 bool                                         `asn1:"-" json:"-"`
	extCount                          int64                                        `asn1:"-" json:"-"`
	extPresent                        []bool                                       `asn1:"-" json:"-"`
	extData                           [][]byte                                     `asn1:"-" json:"-"`
	perPadding                        aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding                     []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin                         []aper.OpaqueOrigin
	extWire                           []aper.WireSpan
}

// MarshalAPER encodes SONInformationReply to APER format.
func (v *SONInformationReply) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SONInformationReply) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(
				previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.X2TNLConfigurationInfo != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if v.X2TNLConfigurationInfo != nil {
		if err := v.X2TNLConfigurationInfo.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding x2TNLConfigurationInfo: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s34.BridgeSONInformationReplyExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:437
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:441
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes SONInformationReply from APER format.
func (v *SONInformationReply) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SONInformationReply with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SONInformationReply) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONInformationReply")
	}
	bb.EnterComponent("SONInformationReply")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONInformationReply")
	}
	padding, err := aper.CaptureFinalBits(bb, "SONInformationReply")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONInformationReply")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SONInformationReply) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONInformationReply{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_x2tnlconfigurationinfo, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_x2tnlconfigurationinfo {
		toleranceMark_x2tnlconfigurationinfo := bb.EnterComponent("X2TNLConfigurationInfo")
		var dec_x2tnlconfigurationinfo X2TNLConfigurationInfo
		if err := dec_x2tnlconfigurationinfo.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "X2TNLConfigurationInfo")
		}
		if err := aper.ChargeValue(bb, dec_x2tnlconfigurationinfo); err != nil {
			return err
		}
		v.X2TNLConfigurationInfo = &dec_x2tnlconfigurationinfo
		bb.LeaveComponent(toleranceMark_x2tnlconfigurationinfo)
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s34.SONInformationReplyExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s34.SONInformationReplyExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s34.BridgeSONInformationReplyExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
		bb.LeaveComponent(toleranceMark_ieextensions)
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:625
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:628
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
			v.extWire = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes X2TNLConfigurationInfo to APER format.
func (v *X2TNLConfigurationInfo) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *X2TNLConfigurationInfo) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(
				previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ENBX2TransportLayerAddresses)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, true, func(fragmentOffset_enbx2transportlayeraddresses, fragmentLength_enbx2transportlayeraddresses int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_enbx2transportlayeraddresses < 0 || fragmentOffset_enbx2transportlayeraddresses > int64(len(v.ENBX2TransportLayerAddresses)) || fragmentLength_enbx2transportlayeraddresses < 0 || fragmentLength_enbx2transportlayeraddresses > int64(len(v.ENBX2TransportLayerAddresses[fragmentOffset_enbx2transportlayeraddresses:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ENBX2TransportLayerAddresses[fragmentOffset_enbx2transportlayeraddresses : fragmentOffset_enbx2transportlayeraddresses+fragmentLength_enbx2transportlayeraddresses] {
			if err := aper.EncodeBitStringAlignedExt(bb, elem.Bytes, elem.BitLength, 1, 160, true, true); err != nil {
				return fmt.Errorf("encoding eNBX2TransportLayerAddresses element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding eNBX2TransportLayerAddresses: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s38.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:437
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:441
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes X2TNLConfigurationInfo from APER format.
func (v *X2TNLConfigurationInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes X2TNLConfigurationInfo with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *X2TNLConfigurationInfo) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "X2TNLConfigurationInfo")
	}
	bb.EnterComponent("X2TNLConfigurationInfo")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "X2TNLConfigurationInfo")
	}
	padding, err := aper.CaptureFinalBits(bb, "X2TNLConfigurationInfo")
	if err != nil {
		return runtime.WrapDecodePath(err, "X2TNLConfigurationInfo")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *X2TNLConfigurationInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = X2TNLConfigurationInfo{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_enbx2transportlayeraddresses := bb.EnterComponent("ENBX2TransportLayerAddresses")
	v.ENBX2TransportLayerAddresses = make(s00.ENBX2TLAs, 0)
	_, errCollection_enbx2transportlayeraddresses := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, true, func(fragmentOffset_enbx2transportlayeraddresses, fragmentLength_enbx2transportlayeraddresses int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_6: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1202
		if fragmentOffset_enbx2transportlayeraddresses < 0 || fragmentLength_enbx2transportlayeraddresses < 0 || fragmentLength_enbx2transportlayeraddresses > int64(^uint(0)>>1) || fragmentOffset_enbx2transportlayeraddresses > int64(^uint(0)>>1)-fragmentLength_enbx2transportlayeraddresses {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_enbx2transportlayeraddresses; i++ {
			elemBytes, elemBitLength, err := aper.DecodeBitStringAlignedExt(bb, 1, 160, true, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ENBX2TransportLayerAddresses[%d]", fragmentOffset_enbx2transportlayeraddresses+i))
			}
			if next, err := aper.AppendValues(bb, v.ENBX2TransportLayerAddresses, runtime.BitString{Bytes: elemBytes, BitLength: elemBitLength}); err != nil {
				return err
			} else {
				v.ENBX2TransportLayerAddresses = next
			}
		}
		return nil
	})
	if errCollection_enbx2transportlayeraddresses != nil {
		return runtime.WrapDecodePath(errCollection_enbx2transportlayeraddresses, "ENBX2TransportLayerAddresses")
	}
	bb.LeaveComponent(toleranceMark_enbx2transportlayeraddresses)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s38.X2TNLConfigurationInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s38.X2TNLConfigurationInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s38.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return runtime.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
		bb.LeaveComponent(toleranceMark_ieextensions)
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:625
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:628
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
			v.extWire = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SONInformationReply) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONInformationReply", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SONInformationReply", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SONInformationReply) WithoutReplay() SONInformationReply {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SONInformationReply
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *X2TNLConfigurationInfo) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "X2TNLConfigurationInfo", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "X2TNLConfigurationInfo", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v X2TNLConfigurationInfo) WithoutReplay() X2TNLConfigurationInfo {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero X2TNLConfigurationInfo
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *SONInformationReply) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SONInformationReply) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SONInformationReply.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SONInformationReply.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SONInformationReply) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SONInformationReply.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SONInformationReply.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *X2TNLConfigurationInfo) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *X2TNLConfigurationInfo) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("X2TNLConfigurationInfo.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("X2TNLConfigurationInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *X2TNLConfigurationInfo) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("X2TNLConfigurationInfo.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("X2TNLConfigurationInfo.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *SONInformationReply) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SONInformationReply")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SONInformationReply) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SONInformationReply")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSONInformationReply(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SONInformationReply")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SONInformationReply")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SONInformationReply) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SONInformationReply")
}
func (v *SONInformationReply) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SONInformationReply")
}
func (v *SONInformationReply) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSONInformationReply(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *SONInformationReply) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SONInformationReply) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *X2TNLConfigurationInfo) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "X2TNLConfigurationInfo")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *X2TNLConfigurationInfo) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "X2TNLConfigurationInfo")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APX2TNLConfigurationInfo(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "X2TNLConfigurationInfo")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "X2TNLConfigurationInfo")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *X2TNLConfigurationInfo) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "X2TNLConfigurationInfo")
}
func (v *X2TNLConfigurationInfo) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "X2TNLConfigurationInfo")
}
func (v *X2TNLConfigurationInfo) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APX2TNLConfigurationInfo(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *X2TNLConfigurationInfo) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *X2TNLConfigurationInfo) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SONInformationReply) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SONInformationReply")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SONInformationReply
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSONInformationReply(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SONInformationReply{}
		return report, aper.OperationError(err, "SONInformationReply")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SONInformationReply")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *X2TNLConfigurationInfo) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "X2TNLConfigurationInfo")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded X2TNLConfigurationInfo
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APX2TNLConfigurationInfo(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = X2TNLConfigurationInfo{}
		return report, aper.OperationError(err, "X2TNLConfigurationInfo")
	}
	*v = decoded
	return report, aper.OperationError(nil, "X2TNLConfigurationInfo")
}

// WriteReplaceWarningRequest represents the ASN.1 type WriteReplaceWarningRequest (SEQUENCE).
type WriteReplaceWarningRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s33.WriteReplaceWarningRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                      `asn1:"-" json:"-"`
	extCount         int64                                     `asn1:"-" json:"-"`
	extPresent       []bool                                    `asn1:"-" json:"-"`
	extData          [][]byte                                  `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// WriteReplaceWarningResponse represents the ASN.1 type WriteReplaceWarningResponse (SEQUENCE).
type WriteReplaceWarningResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s32.WriteReplaceWarningResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                       `asn1:"-" json:"-"`
	extCount         int64                                      `asn1:"-" json:"-"`
	extPresent       []bool                                     `asn1:"-" json:"-"`
	extData          [][]byte                                   `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                          `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                     `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes WriteReplaceWarningRequest to APER format.
func (v *WriteReplaceWarningRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *WriteReplaceWarningRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := s33.BridgeWriteReplaceWarningRequestIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:437
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:441
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes WriteReplaceWarningRequest from APER format.
func (v *WriteReplaceWarningRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WriteReplaceWarningRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WriteReplaceWarningRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "WriteReplaceWarningRequest")
	}
	bb.EnterComponent("WriteReplaceWarningRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "WriteReplaceWarningRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "WriteReplaceWarningRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "WriteReplaceWarningRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *WriteReplaceWarningRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WriteReplaceWarningRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s33.WriteReplaceWarningRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s33.WriteReplaceWarningRequestIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s33.BridgeWriteReplaceWarningRequestIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	bb.LeaveComponent(toleranceMark_protocolies)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:625
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:628
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
			v.extWire = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes WriteReplaceWarningResponse to APER format.
func (v *WriteReplaceWarningResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *WriteReplaceWarningResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := s32.BridgeWriteReplaceWarningResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:437
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:441
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes WriteReplaceWarningResponse from APER format.
func (v *WriteReplaceWarningResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WriteReplaceWarningResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WriteReplaceWarningResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "WriteReplaceWarningResponse")
	}
	bb.EnterComponent("WriteReplaceWarningResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "WriteReplaceWarningResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "WriteReplaceWarningResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "WriteReplaceWarningResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *WriteReplaceWarningResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WriteReplaceWarningResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s32.WriteReplaceWarningResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s32.WriteReplaceWarningResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s32.BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	bb.LeaveComponent(toleranceMark_protocolies)
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:625
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := aper.ChargeSlice[aper.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]aper.OpaqueOrigin, len(v.extData))
		if err := aper.ChargeSlice[aper.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]aper.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:628
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(aper.UnknownExtension, i); err != nil {
					return err
				}
				var retained aper.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
			v.extWire = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WriteReplaceWarningRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "WriteReplaceWarningRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "WriteReplaceWarningRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WriteReplaceWarningRequest) WithoutReplay() WriteReplaceWarningRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero WriteReplaceWarningRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WriteReplaceWarningResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "WriteReplaceWarningResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "WriteReplaceWarningResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WriteReplaceWarningResponse) WithoutReplay() WriteReplaceWarningResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero WriteReplaceWarningResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *WriteReplaceWarningRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *WriteReplaceWarningRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("WriteReplaceWarningRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("WriteReplaceWarningRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *WriteReplaceWarningRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("WriteReplaceWarningRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("WriteReplaceWarningRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *WriteReplaceWarningResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *WriteReplaceWarningResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("WriteReplaceWarningResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("WriteReplaceWarningResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *WriteReplaceWarningResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("WriteReplaceWarningResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("WriteReplaceWarningResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *WriteReplaceWarningRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "WriteReplaceWarningRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *WriteReplaceWarningRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "WriteReplaceWarningRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APWriteReplaceWarningRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "WriteReplaceWarningRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "WriteReplaceWarningRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *WriteReplaceWarningRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "WriteReplaceWarningRequest")
}
func (v *WriteReplaceWarningRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "WriteReplaceWarningRequest")
}
func (v *WriteReplaceWarningRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APWriteReplaceWarningRequest(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *WriteReplaceWarningRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *WriteReplaceWarningRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *WriteReplaceWarningResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "WriteReplaceWarningResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *WriteReplaceWarningResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "WriteReplaceWarningResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APWriteReplaceWarningResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "WriteReplaceWarningResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "WriteReplaceWarningResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *WriteReplaceWarningResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "WriteReplaceWarningResponse")
}
func (v *WriteReplaceWarningResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "WriteReplaceWarningResponse")
}
func (v *WriteReplaceWarningResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APWriteReplaceWarningResponse(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *WriteReplaceWarningResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *WriteReplaceWarningResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *WriteReplaceWarningRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "WriteReplaceWarningRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded WriteReplaceWarningRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APWriteReplaceWarningRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = WriteReplaceWarningRequest{}
		return report, aper.OperationError(err, "WriteReplaceWarningRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "WriteReplaceWarningRequest")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *WriteReplaceWarningResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "WriteReplaceWarningResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded WriteReplaceWarningResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APWriteReplaceWarningResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = WriteReplaceWarningResponse{}
		return report, aper.OperationError(err, "WriteReplaceWarningResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "WriteReplaceWarningResponse")
}

// SuccessfulOutcome represents the ASN.1 type SuccessfulOutcome (SEQUENCE).
type SuccessfulOutcome struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProcedureCode    s00.ProcedureCode    `asn1:"tag:0,context,implicit"`
	Criticality      s00.Criticality      `asn1:"tag:1,context,implicit"`
	Value            SuccessfulValue      `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
	perPadding       aper.CompletePadding `asn1:"-" json:"-"`
}

// MarshalAPER encodes SuccessfulOutcome to APER format.
func (v *SuccessfulOutcome) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SuccessfulOutcome) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(
			previous,
		)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.Value.code != v.ProcedureCode {
		return runtime.WrapDecodePath(fmt.Errorf("%w: procedure code %d does not match its value selector", aper.ErrInvalidValue, v.ProcedureCode), "SuccessfulOutcome.ProcedureCode")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.ProcedureCode), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false); err != nil {
		return fmt.Errorf("encoding procedureCode: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	openData_value, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, openData_value); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes SuccessfulOutcome from APER format.
func (v *SuccessfulOutcome) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SuccessfulOutcome with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SuccessfulOutcome) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SuccessfulOutcome")
	}
	bb.EnterComponent("SuccessfulOutcome")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SuccessfulOutcome")
	}
	padding, err := aper.CaptureFinalBits(bb, "SuccessfulOutcome")
	if err != nil {
		return runtime.WrapDecodePath(err, "SuccessfulOutcome")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SuccessfulOutcome) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SuccessfulOutcome{}
	val_procedurecode, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(255), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProcedureCode")
	}
	v.ProcedureCode = s00.ProcedureCode(val_procedurecode)
	val_criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Criticality"})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Criticality")
	}
	v.Criticality = s00.Criticality(val_criticality)
	toleranceMark_value := bb.EnterComponent("Value")
	opaque_value, err := aper.DecodeOpaqueOpenTypeAligned(bb, s00.SuccessfulReason(v.ProcedureCode), aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "Successful"}})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	opaque_value = opaque_value.WithPath("SuccessfulOutcome.Value")
	decoded_value, err := BridgeDecodeSuccessfulValue(v.ProcedureCode, opaque_value)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	v.Value = decoded_value
	bb.LeaveComponent(toleranceMark_value)
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SuccessfulOutcome) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SuccessfulOutcome", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SuccessfulOutcome", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SuccessfulOutcome) WithoutReplay() SuccessfulOutcome {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SuccessfulOutcome
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *SuccessfulOutcome) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SuccessfulOutcome")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SuccessfulOutcome) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SuccessfulOutcome")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSuccessfulOutcome(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SuccessfulOutcome")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SuccessfulOutcome")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SuccessfulOutcome) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SuccessfulOutcome")
}
func (v *SuccessfulOutcome) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SuccessfulOutcome")
}
func (v *SuccessfulOutcome) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSuccessfulOutcome(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *SuccessfulOutcome) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SuccessfulOutcome) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SuccessfulOutcome) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SuccessfulOutcome")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SuccessfulOutcome
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSuccessfulOutcome(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SuccessfulOutcome{}
		return report, aper.OperationError(err, "SuccessfulOutcome")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SuccessfulOutcome")
}

type SONConfigurationTransferExtIEsValue struct {
	id                            s00.ProtocolIEID
	received                      aper.WireSpan
	replay                        aper.Snapshot
	opaque                        aper.OpaqueOpenType
	isOpaque                      bool
	rowX2TNLConfigurationInfo     *X2TNLConfigurationInfo
	rowSynchronisationInformation *s31.SynchronisationInformation
	rowRequestedTNLInfo           *s26.RequestedTNLInfo
}

func (v SONConfigurationTransferExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(152):
		return v.rowX2TNLConfigurationInfo != nil
	case s00.ProtocolIEID(209):
		return v.rowSynchronisationInformation != nil
	case s00.ProtocolIEID(356):
		return v.rowRequestedTNLInfo != nil
	}
	return false
}

// Opaque returns the retained opaque open value of SONConfigurationTransferExtIEsValue and reports whether the opaque alternative is selected.
func (v *SONConfigurationTransferExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (SONConfigurationTransferExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONConfigurationTransfer-ExtIEs"}}
}
func (SONConfigurationTransferExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(152):
		return aper.UnknownSelector
	case s00.ProtocolIEID(209):
		return aper.UnknownSelector
	case s00.ProtocolIEID(356):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(12):
		return aper.NotInTable
	case s00.ProtocolIEID(13):
		return aper.NotInTable
	case s00.ProtocolIEID(14):
		return aper.NotInTable
	case s00.ProtocolIEID(15):
		return aper.NotInTable
	case s00.ProtocolIEID(16):
		return aper.NotInTable
	case s00.ProtocolIEID(17):
		return aper.NotInTable
	case s00.ProtocolIEID(18):
		return aper.NotInTable
	case s00.ProtocolIEID(19):
		return aper.NotInTable
	case s00.ProtocolIEID(20):
		return aper.NotInTable
	case s00.ProtocolIEID(21):
		return aper.NotInTable
	case s00.ProtocolIEID(22):
		return aper.NotInTable
	case s00.ProtocolIEID(23):
		return aper.NotInTable
	case s00.ProtocolIEID(24):
		return aper.NotInTable
	case s00.ProtocolIEID(25):
		return aper.NotInTable
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsX2TNLConfigurationInfo returns the selected X2TNLConfigurationInfo value of SONConfigurationTransferExtIEsValue and reports whether that alternative is active.
func (v *SONConfigurationTransferExtIEsValue) AsX2TNLConfigurationInfo() (*X2TNLConfigurationInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(152) || v.rowX2TNLConfigurationInfo == nil {
		return nil, false
	}
	return v.rowX2TNLConfigurationInfo, true
}

// AsSynchronisationInformation returns the selected SynchronisationInformation value of SONConfigurationTransferExtIEsValue and reports whether that alternative is active.
func (v *SONConfigurationTransferExtIEsValue) AsSynchronisationInformation() (*s31.SynchronisationInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(209) || v.rowSynchronisationInformation == nil {
		return nil, false
	}
	return v.rowSynchronisationInformation, true
}

// AsRequestedTNLInfo returns the selected RequestedTNLInfo value of SONConfigurationTransferExtIEsValue and reports whether that alternative is active.
func (v *SONConfigurationTransferExtIEsValue) AsRequestedTNLInfo() (*s26.RequestedTNLInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(356) || v.rowRequestedTNLInfo == nil {
		return nil, false
	}
	return v.rowRequestedTNLInfo, true
}
func (v SONConfigurationTransferExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (SONConfigurationTransferExtIEsValue, error) {
	out := SONConfigurationTransferExtIEsValue{id: id}
	switch id {
	case s00.ProtocolIEID(152):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value X2TNLConfigurationInfo
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "X2TNLConfigurationInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "X2TNLConfigurationInfo")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowX2TNLConfigurationInfo = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(209):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s31.SynchronisationInformation
		child := scope
		if err := s31.BridgeSynchronisationInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SynchronisationInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SynchronisationInformation")
		if err != nil {
			return out, err
		}
		*s31.BridgeSynchronisationInformationFieldPerPadding(&value) = padding
		*s31.BridgeSynchronisationInformationFieldReceived(&value) = true
		raw.RetainContents(s31.BridgeSynchronisationInformationFieldReceivedBytes(&value))
		*s31.BridgeSynchronisationInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSynchronisationInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(356):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s26.RequestedTNLInfo
		child := scope
		if err := s26.BridgeRequestedTNLInfoMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "RequestedTNLInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "RequestedTNLInfo")
		if err != nil {
			return out, err
		}
		*s26.BridgeRequestedTNLInfoFieldPerPadding(&value) = padding
		*s26.BridgeRequestedTNLInfoFieldReceived(&value) = true
		raw.RetainContents(s26.BridgeRequestedTNLInfoFieldReceivedBytes(&value))
		*s26.BridgeRequestedTNLInfoFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowRequestedTNLInfo = &value
		raw.RetainContents(&out.received)
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v SONConfigurationTransferExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v SONConfigurationTransferExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if budget == nil {
		var err error
		budget, err = aper.EncodeBudget()
		if err != nil {
			return nil, err
		}
	}
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	case s00.ProtocolIEID(152):
		if v.rowX2TNLConfigurationInfo == nil {
			return nil, fmt.Errorf("%s missing value", "SONConfigurationTransfer-ExtIEs.id-x2TNLConfigurationInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowX2TNLConfigurationInfo.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(209):
		if v.rowSynchronisationInformation == nil {
			return nil, fmt.Errorf("%s missing value", "SONConfigurationTransfer-ExtIEs.id-Synchronisation-Information:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s31.BridgeSynchronisationInformationMethodMarshalAPERBudget(v.rowSynchronisationInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(356):
		if v.rowRequestedTNLInfo == nil {
			return nil, fmt.Errorf("%s missing value", "SONConfigurationTransfer-ExtIEs.id-RequestedTNLInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s26.BridgeRequestedTNLInfoMethodMarshalAPERBudget(v.rowRequestedTNLInfo, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "SONConfigurationTransferExtIEsValue:", v.id)
	}
}

// SuccessfulOutcomeCodec binds the complete source value type.
func SuccessfulOutcomeCodec() SuccessfulOutcomeValueCodec {
	return SuccessfulOutcomeValueCodec{path: "SuccessfulOutcome", decode: func(data []byte, options aper.DecodeState) (SuccessfulOutcome, error) {
		var value SuccessfulOutcome
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SuccessfulOutcome{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SuccessfulOutcome, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SuccessfulOutcome, options aper.DecodeState) (SuccessfulOutcome, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSuccessfulOutcome(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root

	}, compare: func(v SuccessfulOutcome, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSuccessfulOutcome(&v, &s)
		s.End(f, root, false)
		return s.
			Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SuccessfulOutcome"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func BridgeValidateHandoverRequiredBudget(v *s34.HandoverRequired, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverRequired")
	}
	rows := []s00.FieldInfo{s34.HandoverRequiredIEs().MMEUES1APID().Info(), s34.HandoverRequiredIEs().ENBUES1APID().Info(), s34.HandoverRequiredIEs().HandoverType().Info(), s34.HandoverRequiredIEs().Cause().Info(), s34.HandoverRequiredIEs().TargetID().Info(), s34.HandoverRequiredIEs().DirectForwardingPathAvailability().Info(), s34.HandoverRequiredIEs().SRVCCHOIndication().Info(), s34.HandoverRequiredIEs().SourceToTargetTransparentContainer().Info(), s34.HandoverRequiredIEs().SourceToTargetTransparentContainerSecondary().Info(), s34.HandoverRequiredIEs().MSClassmark2().Info(), s34.HandoverRequiredIEs().MSClassmark3().Info(), s34.HandoverRequiredIEs().CSGId().Info(), s34.HandoverRequiredIEs().CellAccessMode().Info(), s34.HandoverRequiredIEs().PSServiceNotAvailable().Info()}
	report := s34.BridgeHandoverRequiredIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverRequired.protocolIEs", budget)
	BridgeWalkValidationHandoverRequired(v, &report, "HandoverRequired", true)
	return report, nil
}
func BridgeValidateHandoverRequestBudget(v *s49.HandoverRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverRequest")
	}
	rows := []s00.FieldInfo{s48.HandoverRequestIEs().MMEUES1APID().Info(), s48.HandoverRequestIEs().HandoverType().Info(), s48.HandoverRequestIEs().Cause().Info(), s48.HandoverRequestIEs().UEaggregateMaximumBitrate().Info(), s48.HandoverRequestIEs().ERABToBeSetupListHOReq().Info(), s48.HandoverRequestIEs().SourceToTargetTransparentContainer().Info(), s48.HandoverRequestIEs().UESecurityCapabilities().Info(), s48.HandoverRequestIEs().HandoverRestrictionList().Info(), s48.HandoverRequestIEs().TraceActivation().Info(), s48.HandoverRequestIEs().RequestType().Info(), s48.HandoverRequestIEs().SRVCCOperationPossible().Info(), s48.HandoverRequestIEs().SecurityContext().Info(), s48.HandoverRequestIEs().NASSecurityParameterstoEUTRAN().Info(), s48.HandoverRequestIEs().CSGId().Info(), s48.HandoverRequestIEs().CSGMembershipStatus().Info(), s48.HandoverRequestIEs().GUMMEIID().Info(), s48.HandoverRequestIEs().MMEUES1APID2().Info(), s48.HandoverRequestIEs().ManagementBasedMDTAllowed().Info(), s48.HandoverRequestIEs().ManagementBasedMDTPLMNList().Info(), s48.HandoverRequestIEs().MaskedIMEISV().Info(), s48.HandoverRequestIEs().ExpectedUEBehaviour().Info(), s48.HandoverRequestIEs().ProSeAuthorized().Info(), s48.HandoverRequestIEs().UEUserPlaneCIoTSupportIndicator().Info(), s48.HandoverRequestIEs().V2XServicesAuthorized().Info(), s48.HandoverRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s48.HandoverRequestIEs().EnhancedCoverageRestricted().Info(), s48.HandoverRequestIEs().NRUESecurityCapabilities().Info(), s48.HandoverRequestIEs().CEModeBRestricted().Info(), s48.HandoverRequestIEs().AerialUEsubscriptionInformation().Info(), s48.HandoverRequestIEs().PendingDataIndication().Info(), s48.HandoverRequestIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s48.HandoverRequestIEs().AdditionalRRMPriorityIndex().Info(), s48.HandoverRequestIEs().IABAuthorized().Info(), s48.HandoverRequestIEs().NRV2XServicesAuthorized().Info(), s48.HandoverRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s48.HandoverRequestIEs().PC5QoSParameters().Info(), s48.HandoverRequestIEs().UERadioCapabilityID().Info(), s48.HandoverRequestIEs().TimeRefDistribution().Info()}
	report := s49.BridgeHandoverRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverRequest.protocolIEs", budget)
	BridgeWalkValidationHandoverRequest(v, &report, "HandoverRequest", true)
	return report, nil
}
func BridgeValidateHandoverNotifyBudget(v *s35.HandoverNotify, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverNotify")
	}
	rows := []s00.FieldInfo{s35.HandoverNotifyIEs().MMEUES1APID().Info(), s35.HandoverNotifyIEs().ENBUES1APID().Info(), s35.HandoverNotifyIEs().EUTRANCGI().Info(), s35.HandoverNotifyIEs().TAI().Info(), s35.HandoverNotifyIEs().TunnelInformationForBBF().Info(), s35.HandoverNotifyIEs().LHNID().Info(), s35.HandoverNotifyIEs().PSCellInformation().Info(), s35.HandoverNotifyIEs().NotifySourceeNB().Info(), s35.HandoverNotifyIEs().LTENTNTAIInformation().Info()}
	report := s35.BridgeHandoverNotifyIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverNotify.protocolIEs", budget)
	BridgeWalkValidationHandoverNotify(v, &report, "HandoverNotify", true)
	return report, nil
}
func BridgeValidatePathSwitchRequestBudget(v *s41.PathSwitchRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil PathSwitchRequest")
	}
	rows := []s00.FieldInfo{s41.PathSwitchRequestIEs().ENBUES1APID().Info(), s41.PathSwitchRequestIEs().ERABToBeSwitchedDLList().Info(), s41.PathSwitchRequestIEs().SourceMMEUES1APID().Info(), s41.PathSwitchRequestIEs().EUTRANCGI().Info(), s41.PathSwitchRequestIEs().TAI().Info(), s41.PathSwitchRequestIEs().UESecurityCapabilities().Info(), s41.PathSwitchRequestIEs().CSGId().Info(), s41.PathSwitchRequestIEs().CellAccessMode().Info(), s41.PathSwitchRequestIEs().SourceMMEGUMMEI().Info(), s41.PathSwitchRequestIEs().CSGMembershipStatus().Info(), s41.PathSwitchRequestIEs().TunnelInformationForBBF().Info(), s41.PathSwitchRequestIEs().LHNID().Info(), s41.PathSwitchRequestIEs().RRCResumeCause().Info(), s41.PathSwitchRequestIEs().NRUESecurityCapabilities().Info(), s41.PathSwitchRequestIEs().PSCellInformation().Info(), s41.PathSwitchRequestIEs().LTENTNTAIInformation().Info()}
	report := s41.BridgePathSwitchRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "PathSwitchRequest.protocolIEs", budget)
	BridgeWalkValidationPathSwitchRequest(v, &report, "PathSwitchRequest", true)
	return report, nil
}
func BridgeValidatePathSwitchRequestAcknowledgeBudget(v *s47.PathSwitchRequestAcknowledge, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil PathSwitchRequestAcknowledge")
	}
	rows := []s00.FieldInfo{s47.PathSwitchRequestAcknowledgeIEs().MMEUES1APID().Info(), s47.PathSwitchRequestAcknowledgeIEs().ENBUES1APID().Info(), s47.PathSwitchRequestAcknowledgeIEs().UEaggregateMaximumBitrate().Info(), s47.PathSwitchRequestAcknowledgeIEs().ERABToBeSwitchedULList().Info(), s47.PathSwitchRequestAcknowledgeIEs().ERABToBeReleasedList().Info(), s47.PathSwitchRequestAcknowledgeIEs().SecurityContext().Info(), s47.PathSwitchRequestAcknowledgeIEs().CriticalityDiagnostics().Info(), s47.PathSwitchRequestAcknowledgeIEs().MMEUES1APID2().Info(), s47.PathSwitchRequestAcknowledgeIEs().CSGMembershipStatus().Info(), s47.PathSwitchRequestAcknowledgeIEs().ProSeAuthorized().Info(), s47.PathSwitchRequestAcknowledgeIEs().UEUserPlaneCIoTSupportIndicator().Info(), s47.PathSwitchRequestAcknowledgeIEs().V2XServicesAuthorized().Info(), s47.PathSwitchRequestAcknowledgeIEs().UESidelinkAggregateMaximumBitrate().Info(), s47.PathSwitchRequestAcknowledgeIEs().EnhancedCoverageRestricted().Info(), s47.PathSwitchRequestAcknowledgeIEs().NRUESecurityCapabilities().Info(), s47.PathSwitchRequestAcknowledgeIEs().CEModeBRestricted().Info(), s47.PathSwitchRequestAcknowledgeIEs().AerialUEsubscriptionInformation().Info(), s47.PathSwitchRequestAcknowledgeIEs().PendingDataIndication().Info(), s47.PathSwitchRequestAcknowledgeIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s47.PathSwitchRequestAcknowledgeIEs().HandoverRestrictionList().Info(), s47.PathSwitchRequestAcknowledgeIEs().AdditionalRRMPriorityIndex().Info(), s47.PathSwitchRequestAcknowledgeIEs().NRV2XServicesAuthorized().Info(), s47.PathSwitchRequestAcknowledgeIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s47.PathSwitchRequestAcknowledgeIEs().PC5QoSParameters().Info(), s47.PathSwitchRequestAcknowledgeIEs().UERadioCapabilityID().Info(), s47.PathSwitchRequestAcknowledgeIEs().UESecurityCapabilities().Info(), s47.PathSwitchRequestAcknowledgeIEs().ERABToBeUpdatedList().Info(), s47.PathSwitchRequestAcknowledgeIEs().TimeRefDistribution().Info()}
	report := s47.BridgePathSwitchRequestAcknowledgeIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "PathSwitchRequestAcknowledge.protocolIEs", budget)
	BridgeWalkValidationPathSwitchRequestAcknowledge(v, &report, "PathSwitchRequestAcknowledge", true)
	return report, nil
}
func BridgeValidateERABSetupRequestBudget(v *s40.ERABSetupRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABSetupRequest")
	}
	rows := []s00.FieldInfo{s40.ERABSetupRequestIEs().MMEUES1APID().Info(), s40.ERABSetupRequestIEs().ENBUES1APID().Info(), s40.ERABSetupRequestIEs().UEaggregateMaximumBitrate().Info(), s40.ERABSetupRequestIEs().ERABToBeSetupListBearerSUReq().Info()}
	report := s40.BridgeERABSetupRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABSetupRequest.protocolIEs", budget)
	BridgeWalkValidationERABSetupRequest(v, &report, "ERABSetupRequest", true)
	return report, nil
}
func BridgeValidateERABSetupResponseBudget(v *s46.ERABSetupResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABSetupResponse")
	}
	rows := []s00.FieldInfo{s45.ERABSetupResponseIEs().MMEUES1APID().Info(), s45.ERABSetupResponseIEs().ENBUES1APID().Info(), s45.ERABSetupResponseIEs().ERABSetupListBearerSURes().Info(), s45.ERABSetupResponseIEs().ERABFailedToSetupListBearerSURes().Info(), s45.ERABSetupResponseIEs().CriticalityDiagnostics().Info(), s45.ERABSetupResponseIEs().UserLocationInformation().Info()}
	report := s46.BridgeERABSetupResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABSetupResponse.protocolIEs", budget)
	BridgeWalkValidationERABSetupResponse(v, &report, "ERABSetupResponse", true)
	return report, nil
}
func BridgeValidateERABModifyRequestBudget(v *s40.ERABModifyRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABModifyRequest")
	}
	rows := []s00.FieldInfo{s40.ERABModifyRequestIEs().MMEUES1APID().Info(), s40.ERABModifyRequestIEs().ENBUES1APID().Info(), s40.ERABModifyRequestIEs().UEaggregateMaximumBitrate().Info(), s40.ERABModifyRequestIEs().ERABToBeModifiedListBearerModReq().Info(), s40.ERABModifyRequestIEs().SecondaryRATDataUsageRequest().Info()}
	report := s40.BridgeERABModifyRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABModifyRequest.protocolIEs", budget)
	BridgeWalkValidationERABModifyRequest(v, &report, "ERABModifyRequest", true)
	return report, nil
}
func BridgeValidateERABModifyResponseBudget(v *s46.ERABModifyResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABModifyResponse")
	}
	rows := []s00.FieldInfo{s45.ERABModifyResponseIEs().MMEUES1APID().Info(), s45.ERABModifyResponseIEs().ENBUES1APID().Info(), s45.ERABModifyResponseIEs().ERABModifyListBearerModRes().Info(), s45.ERABModifyResponseIEs().ERABFailedToModifyList().Info(), s45.ERABModifyResponseIEs().CriticalityDiagnostics().Info(), s45.ERABModifyResponseIEs().SecondaryRATDataUsageReportList().Info(), s45.ERABModifyResponseIEs().UserLocationInformation().Info()}
	report := s46.BridgeERABModifyResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABModifyResponse.protocolIEs", budget)
	BridgeWalkValidationERABModifyResponse(v, &report, "ERABModifyResponse", true)
	return report, nil
}
func BridgeValidateERABReleaseCommandBudget(v *s39.ERABReleaseCommand, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABReleaseCommand")
	}
	rows := []s00.FieldInfo{s39.ERABReleaseCommandIEs().MMEUES1APID().Info(), s39.ERABReleaseCommandIEs().ENBUES1APID().Info(), s39.ERABReleaseCommandIEs().UEaggregateMaximumBitrate().Info(), s39.ERABReleaseCommandIEs().ERABToBeReleasedList().Info(), s39.ERABReleaseCommandIEs().NASPDU().Info()}
	report := s39.BridgeERABReleaseCommandIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABReleaseCommand.protocolIEs", budget)
	BridgeWalkValidationERABReleaseCommand(v, &report, "ERABReleaseCommand", true)
	return report, nil
}
func BridgeValidateERABReleaseResponseBudget(v *s46.ERABReleaseResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABReleaseResponse")
	}
	rows := []s00.FieldInfo{s45.ERABReleaseResponseIEs().MMEUES1APID().Info(), s45.ERABReleaseResponseIEs().ENBUES1APID().Info(), s45.ERABReleaseResponseIEs().ERABReleaseListBearerRelComp().Info(), s45.ERABReleaseResponseIEs().ERABFailedToReleaseList().Info(), s45.ERABReleaseResponseIEs().CriticalityDiagnostics().Info(), s45.ERABReleaseResponseIEs().UserLocationInformation().Info(), s45.ERABReleaseResponseIEs().SecondaryRATDataUsageReportList().Info()}
	report := s46.BridgeERABReleaseResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABReleaseResponse.protocolIEs", budget)
	BridgeWalkValidationERABReleaseResponse(v, &report, "ERABReleaseResponse", true)
	return report, nil
}
func BridgeValidateERABReleaseIndicationBudget(v *s46.ERABReleaseIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABReleaseIndication")
	}
	rows := []s00.FieldInfo{s45.ERABReleaseIndicationIEs().MMEUES1APID().Info(), s45.ERABReleaseIndicationIEs().ENBUES1APID().Info(), s45.ERABReleaseIndicationIEs().ERABReleasedList().Info(), s45.ERABReleaseIndicationIEs().UserLocationInformation().Info(), s45.ERABReleaseIndicationIEs().SecondaryRATDataUsageReportList().Info()}
	report := s46.BridgeERABReleaseIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABReleaseIndication.protocolIEs", budget)
	BridgeWalkValidationERABReleaseIndication(v, &report, "ERABReleaseIndication", true)
	return report, nil
}
func BridgeValidateInitialContextSetupRequestBudget(v *s49.InitialContextSetupRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil InitialContextSetupRequest")
	}
	rows := []s00.FieldInfo{s48.InitialContextSetupRequestIEs().MMEUES1APID().Info(), s48.InitialContextSetupRequestIEs().ENBUES1APID().Info(), s48.InitialContextSetupRequestIEs().UEaggregateMaximumBitrate().Info(), s48.InitialContextSetupRequestIEs().ERABToBeSetupListCtxtSUReq().Info(), s48.InitialContextSetupRequestIEs().UESecurityCapabilities().Info(), s48.InitialContextSetupRequestIEs().SecurityKey().Info(), s48.InitialContextSetupRequestIEs().TraceActivation().Info(), s48.InitialContextSetupRequestIEs().HandoverRestrictionList().Info(), s48.InitialContextSetupRequestIEs().UERadioCapability().Info(), s48.InitialContextSetupRequestIEs().SubscriberProfileIDforRFP().Info(), s48.InitialContextSetupRequestIEs().CSFallbackIndicator().Info(), s48.InitialContextSetupRequestIEs().SRVCCOperationPossible().Info(), s48.InitialContextSetupRequestIEs().CSGMembershipStatus().Info(), s48.InitialContextSetupRequestIEs().RegisteredLAI().Info(), s48.InitialContextSetupRequestIEs().GUMMEIID().Info(), s48.InitialContextSetupRequestIEs().MMEUES1APID2().Info(), s48.InitialContextSetupRequestIEs().ManagementBasedMDTAllowed().Info(), s48.InitialContextSetupRequestIEs().ManagementBasedMDTPLMNList().Info(), s48.InitialContextSetupRequestIEs().AdditionalCSFallbackIndicator().Info(), s48.InitialContextSetupRequestIEs().MaskedIMEISV().Info(), s48.InitialContextSetupRequestIEs().ExpectedUEBehaviour().Info(), s48.InitialContextSetupRequestIEs().ProSeAuthorized().Info(), s48.InitialContextSetupRequestIEs().UEUserPlaneCIoTSupportIndicator().Info(), s48.InitialContextSetupRequestIEs().V2XServicesAuthorized().Info(), s48.InitialContextSetupRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s48.InitialContextSetupRequestIEs().EnhancedCoverageRestricted().Info(), s48.InitialContextSetupRequestIEs().NRUESecurityCapabilities().Info(), s48.InitialContextSetupRequestIEs().CEModeBRestricted().Info(), s48.InitialContextSetupRequestIEs().AerialUEsubscriptionInformation().Info(), s48.InitialContextSetupRequestIEs().PendingDataIndication().Info(), s48.InitialContextSetupRequestIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s48.InitialContextSetupRequestIEs().AdditionalRRMPriorityIndex().Info(), s48.InitialContextSetupRequestIEs().IABAuthorized().Info(), s48.InitialContextSetupRequestIEs().NRV2XServicesAuthorized().Info(), s48.InitialContextSetupRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s48.InitialContextSetupRequestIEs().PC5QoSParameters().Info(), s48.InitialContextSetupRequestIEs().UERadioCapabilityID().Info(), s48.InitialContextSetupRequestIEs().CoarseUELocation().Info(), s48.InitialContextSetupRequestIEs().TimeRefDistribution().Info()}
	report := s49.BridgeInitialContextSetupRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "InitialContextSetupRequest.protocolIEs", budget)
	BridgeWalkValidationInitialContextSetupRequest(v, &report, "InitialContextSetupRequest", true)
	return report, nil
}
func BridgeValidatePagingBudget(v *s49.Paging, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil Paging")
	}
	rows := []s00.FieldInfo{s49.PagingIEs().UEIdentityIndexValue().Info(), s49.PagingIEs().UEPagingID().Info(), s49.PagingIEs().PagingDRX().Info(), s49.PagingIEs().CNDomain().Info(), s49.PagingIEs().TAIList().Info(), s49.PagingIEs().CSGIdList().Info(), s49.PagingIEs().PagingPriority().Info(), s49.PagingIEs().UERadioCapabilityForPaging().Info(), s49.PagingIEs().AssistanceDataForPaging().Info(), s49.PagingIEs().PagingEDRXInformation().Info(), s49.PagingIEs().ExtendedUEIdentityIndexValue().Info(), s49.PagingIEs().NBIoTPagingEDRXInformation().Info(), s49.PagingIEs().NBIoTUEIdentityIndexValue().Info(), s49.PagingIEs().EnhancedCoverageRestricted().Info(), s49.PagingIEs().CEModeBRestricted().Info(), s49.PagingIEs().DataSize().Info(), s49.PagingIEs().WUSAssistanceInformation().Info(), s49.PagingIEs().NBIoTPagingDRX().Info(), s49.PagingIEs().PagingCause().Info()}
	report := s49.BridgePagingIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "Paging.protocolIEs", budget)
	BridgeWalkValidationPaging(v, &report, "Paging", true)
	return report, nil
}
func BridgeValidateDownlinkNASTransportBudget(v *s42.DownlinkNASTransport, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil DownlinkNASTransport")
	}
	rows := []s00.FieldInfo{s42.DownlinkNASTransportIEs().MMEUES1APID().Info(), s42.DownlinkNASTransportIEs().ENBUES1APID().Info(), s42.DownlinkNASTransportIEs().NASPDU().Info(), s42.DownlinkNASTransportIEs().HandoverRestrictionList().Info(), s42.DownlinkNASTransportIEs().SubscriberProfileIDforRFP().Info(), s42.DownlinkNASTransportIEs().SRVCCOperationPossible().Info(), s42.DownlinkNASTransportIEs().UERadioCapability().Info(), s42.DownlinkNASTransportIEs().DLNASPDUDeliveryAckRequest().Info(), s42.DownlinkNASTransportIEs().EnhancedCoverageRestricted().Info(), s42.DownlinkNASTransportIEs().NRUESecurityCapabilities().Info(), s42.DownlinkNASTransportIEs().CEModeBRestricted().Info(), s42.DownlinkNASTransportIEs().UECapabilityInfoRequest().Info(), s42.DownlinkNASTransportIEs().EndIndication().Info(), s42.DownlinkNASTransportIEs().PendingDataIndication().Info(), s42.DownlinkNASTransportIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s42.DownlinkNASTransportIEs().AdditionalRRMPriorityIndex().Info(), s42.DownlinkNASTransportIEs().UERadioCapabilityID().Info(), s42.DownlinkNASTransportIEs().MaskedIMEISV().Info(), s42.DownlinkNASTransportIEs().CoarseUELocation().Info()}
	report := s42.BridgeDownlinkNASTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "DownlinkNASTransport.protocolIEs", budget)
	BridgeWalkValidationDownlinkNASTransport(v, &report, "DownlinkNASTransport", true)
	return report, nil
}
func BridgeValidateInitialUEMessageBudget(v *s35.InitialUEMessage, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil InitialUEMessage")
	}
	rows := []s00.FieldInfo{s35.InitialUEMessageIEs().ENBUES1APID().Info(), s35.InitialUEMessageIEs().NASPDU().Info(), s35.InitialUEMessageIEs().TAI().Info(), s35.InitialUEMessageIEs().EUTRANCGI().Info(), s35.InitialUEMessageIEs().RRCEstablishmentCause().Info(), s35.InitialUEMessageIEs().STMSI().Info(), s35.InitialUEMessageIEs().CSGId().Info(), s35.InitialUEMessageIEs().GUMMEIID().Info(), s35.InitialUEMessageIEs().CellAccessMode().Info(), s35.InitialUEMessageIEs().GWTransportLayerAddress().Info(), s35.InitialUEMessageIEs().RelayNodeIndicator().Info(), s35.InitialUEMessageIEs().GUMMEIType().Info(), s35.InitialUEMessageIEs().TunnelInformationForBBF().Info(), s35.InitialUEMessageIEs().SIPTOLGWTransportLayerAddress().Info(), s35.InitialUEMessageIEs().LHNID().Info(), s35.InitialUEMessageIEs().MMEGroupID().Info(), s35.InitialUEMessageIEs().UEUsageType().Info(), s35.InitialUEMessageIEs().CEModeBSupportIndicator().Info(), s35.InitialUEMessageIEs().DCNID().Info(), s35.InitialUEMessageIEs().CoverageLevel().Info(), s35.InitialUEMessageIEs().UEApplicationLayerMeasurementCapability().Info(), s35.InitialUEMessageIEs().EDTSession().Info(), s35.InitialUEMessageIEs().IABNodeIndication().Info(), s35.InitialUEMessageIEs().LTENTNTAIInformation().Info(), s35.InitialUEMessageIEs().CoarseUELocationRequested().Info()}
	report := s35.BridgeInitialUEMessageIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "InitialUEMessage.protocolIEs", budget)
	BridgeWalkValidationInitialUEMessage(v, &report, "InitialUEMessage", true)
	return report, nil
}
func BridgeValidateUplinkNASTransportBudget(v *s44.UplinkNASTransport, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UplinkNASTransport")
	}
	rows := []s00.FieldInfo{s32.UplinkNASTransportIEs().MMEUES1APID().Info(), s32.UplinkNASTransportIEs().ENBUES1APID().Info(), s32.UplinkNASTransportIEs().NASPDU().Info(), s32.UplinkNASTransportIEs().EUTRANCGI().Info(), s32.UplinkNASTransportIEs().TAI().Info(), s32.UplinkNASTransportIEs().GWTransportLayerAddress().Info(), s32.UplinkNASTransportIEs().SIPTOLGWTransportLayerAddress().Info(), s32.UplinkNASTransportIEs().LHNID().Info(), s32.UplinkNASTransportIEs().PSCellInformation().Info(), s32.UplinkNASTransportIEs().LTENTNTAIInformation().Info()}
	report := s44.BridgeUplinkNASTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UplinkNASTransport.protocolIEs", budget)
	BridgeWalkValidationUplinkNASTransport(v, &report, "UplinkNASTransport", true)
	return report, nil
}
func BridgeValidateResetBudget(v *s36.Reset, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil Reset")
	}
	rows := []s00.FieldInfo{s36.ResetIEs().Cause().Info(), s36.ResetIEs().ResetType().Info()}
	report := s36.BridgeResetIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "Reset.protocolIEs", budget)
	BridgeWalkValidationReset(v, &report, "Reset", true)
	return report, nil
}
func BridgeValidateResetAcknowledgeBudget(v *s44.ResetAcknowledge, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ResetAcknowledge")
	}
	rows := []s00.FieldInfo{s44.ResetAcknowledgeIEs().UEAssociatedLogicalS1ConnectionListResAck().Info(), s44.ResetAcknowledgeIEs().CriticalityDiagnostics().Info()}
	report := s44.BridgeResetAcknowledgeIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ResetAcknowledge.protocolIEs", budget)
	BridgeWalkValidationResetAcknowledge(v, &report, "ResetAcknowledge", true)
	return report, nil
}
func BridgeValidateS1SetupRequestBudget(v *s44.S1SetupRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1SetupRequest")
	}
	rows := []s00.FieldInfo{s43.S1SetupRequestIEs().GlobalENBID().Info(), s43.S1SetupRequestIEs().ENBname().Info(), s43.S1SetupRequestIEs().SupportedTAs().Info(), s43.S1SetupRequestIEs().DefaultPagingDRX().Info(), s43.S1SetupRequestIEs().CSGIdList().Info(), s43.S1SetupRequestIEs().UERetentionInformation().Info(), s43.S1SetupRequestIEs().NBIoTDefaultPagingDRX().Info(), s43.S1SetupRequestIEs().ConnectedengNBList().Info()}
	report := s44.BridgeS1SetupRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "S1SetupRequest.protocolIEs", budget)
	BridgeWalkValidationS1SetupRequest(v, &report, "S1SetupRequest", true)
	return report, nil
}
func BridgeValidateS1SetupResponseBudget(v *s43.S1SetupResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1SetupResponse")
	}
	rows := []s00.FieldInfo{s43.S1SetupResponseIEs().MMEname().Info(), s43.S1SetupResponseIEs().ServedGUMMEIs().Info(), s43.S1SetupResponseIEs().RelativeMMECapacity().Info(), s43.S1SetupResponseIEs().MMERelaySupportIndicator().Info(), s43.S1SetupResponseIEs().CriticalityDiagnostics().Info(), s43.S1SetupResponseIEs().UERetentionInformation().Info(), s43.S1SetupResponseIEs().ServedDCNs().Info(), s43.S1SetupResponseIEs().IABSupported().Info()}
	report := s43.BridgeS1SetupResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "S1SetupResponse.protocolIEs", budget)
	BridgeWalkValidationS1SetupResponse(v, &report, "S1SetupResponse", true)
	return report, nil
}
func BridgeValidateUEContextReleaseRequestBudget(v *s43.UEContextReleaseRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextReleaseRequest")
	}
	rows := []s00.FieldInfo{s43.UEContextReleaseRequestIEs().MMEUES1APID().Info(), s43.UEContextReleaseRequestIEs().ENBUES1APID().Info(), s43.UEContextReleaseRequestIEs().Cause().Info(), s43.UEContextReleaseRequestIEs().GWContextReleaseIndication().Info(), s43.UEContextReleaseRequestIEs().SecondaryRATDataUsageReportList().Info()}
	report := s43.BridgeUEContextReleaseRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextReleaseRequest.protocolIEs", budget)
	BridgeWalkValidationUEContextReleaseRequest(v, &report, "UEContextReleaseRequest", true)
	return report, nil
}
func BridgeValidateUplinkS1cdma2000tunnellingBudget(v *s44.UplinkS1cdma2000tunnelling, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UplinkS1cdma2000tunnelling")
	}
	rows := []s00.FieldInfo{s21.UplinkS1cdma2000tunnellingIEs().MMEUES1APID().Info(), s21.UplinkS1cdma2000tunnellingIEs().ENBUES1APID().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000RATType().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000SectorID().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000HORequiredIndication().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000OneXSRVCCInfo().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000OneXRAND().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000PDU().Info(), s21.UplinkS1cdma2000tunnellingIEs().EUTRANRoundTripDelayEstimationInfo().Info()}
	report := s44.BridgeUplinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UplinkS1cdma2000tunnelling.protocolIEs", budget)
	BridgeWalkValidationUplinkS1cdma2000tunnelling(v, &report, "UplinkS1cdma2000tunnelling", true)
	return report, nil
}
func BridgeValidateUEContextModificationRequestBudget(v *s47.UEContextModificationRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextModificationRequest")
	}
	rows := []s00.FieldInfo{s47.UEContextModificationRequestIEs().MMEUES1APID().Info(), s47.UEContextModificationRequestIEs().ENBUES1APID().Info(), s47.UEContextModificationRequestIEs().SecurityKey().Info(), s47.UEContextModificationRequestIEs().SubscriberProfileIDforRFP().Info(), s47.UEContextModificationRequestIEs().UEaggregateMaximumBitrate().Info(), s47.UEContextModificationRequestIEs().CSFallbackIndicator().Info(), s47.UEContextModificationRequestIEs().UESecurityCapabilities().Info(), s47.UEContextModificationRequestIEs().CSGMembershipStatus().Info(), s47.UEContextModificationRequestIEs().RegisteredLAI().Info(), s47.UEContextModificationRequestIEs().AdditionalCSFallbackIndicator().Info(), s47.UEContextModificationRequestIEs().ProSeAuthorized().Info(), s47.UEContextModificationRequestIEs().SRVCCOperationPossible().Info(), s47.UEContextModificationRequestIEs().SRVCCOperationNotPossible().Info(), s47.UEContextModificationRequestIEs().V2XServicesAuthorized().Info(), s47.UEContextModificationRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s47.UEContextModificationRequestIEs().NRUESecurityCapabilities().Info(), s47.UEContextModificationRequestIEs().AerialUEsubscriptionInformation().Info(), s47.UEContextModificationRequestIEs().AdditionalRRMPriorityIndex().Info(), s47.UEContextModificationRequestIEs().IABAuthorized().Info(), s47.UEContextModificationRequestIEs().NRV2XServicesAuthorized().Info(), s47.UEContextModificationRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s47.UEContextModificationRequestIEs().PC5QoSParameters().Info(), s47.UEContextModificationRequestIEs().UERadioCapabilityID().Info(), s47.UEContextModificationRequestIEs().TimeRefDistribution().Info()}
	report := s47.BridgeUEContextModificationRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextModificationRequest.protocolIEs", budget)
	BridgeWalkValidationUEContextModificationRequest(v, &report, "UEContextModificationRequest", true)
	return report, nil
}
func BridgeValidateUEContextModificationResponseBudget(v *s36.UEContextModificationResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextModificationResponse")
	}
	rows := []s00.FieldInfo{s23.UEContextModificationResponseIEs().MMEUES1APID().Info(), s23.UEContextModificationResponseIEs().ENBUES1APID().Info(), s23.UEContextModificationResponseIEs().CriticalityDiagnostics().Info()}
	report := s36.BridgeUEContextModificationResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextModificationResponse.protocolIEs", budget)
	BridgeWalkValidationUEContextModificationResponse(v, &report, "UEContextModificationResponse", true)
	return report, nil
}
func BridgeValidateUEContextModificationFailureBudget(v *s36.UEContextModificationFailure, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextModificationFailure")
	}
	rows := []s00.FieldInfo{s23.UEContextModificationFailureIEs().MMEUES1APID().Info(), s23.UEContextModificationFailureIEs().ENBUES1APID().Info(), s23.UEContextModificationFailureIEs().Cause().Info(), s23.UEContextModificationFailureIEs().CriticalityDiagnostics().Info()}
	report := s36.BridgeUEContextModificationFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextModificationFailure.protocolIEs", budget)
	BridgeWalkValidationUEContextModificationFailure(v, &report, "UEContextModificationFailure", true)
	return report, nil
}
func BridgeValidateUECapabilityInfoIndicationBudget(v *s36.UECapabilityInfoIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UECapabilityInfoIndication")
	}
	rows := []s00.FieldInfo{s12.UECapabilityInfoIndicationIEs().MMEUES1APID().Info(), s12.UECapabilityInfoIndicationIEs().ENBUES1APID().Info(), s12.UECapabilityInfoIndicationIEs().UERadioCapability().Info(), s12.UECapabilityInfoIndicationIEs().UERadioCapabilityForPaging().Info(), s12.UECapabilityInfoIndicationIEs().UEApplicationLayerMeasurementCapability().Info(), s12.UECapabilityInfoIndicationIEs().LTEMIndication().Info(), s12.UECapabilityInfoIndicationIEs().UERadioCapabilityNRFormat().Info(), s12.UECapabilityInfoIndicationIEs().UERadioCapabilityForPagingNRFormat().Info()}
	report := s36.BridgeUECapabilityInfoIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UECapabilityInfoIndication.protocolIEs", budget)
	BridgeWalkValidationUECapabilityInfoIndication(v, &report, "UECapabilityInfoIndication", true)
	return report, nil
}
func BridgeValidateUEContextReleaseCommandBudget(v *s37.UEContextReleaseCommand, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextReleaseCommand")
	}
	rows := []s00.FieldInfo{s37.UEContextReleaseCommandIEs().UES1APIDs().Info(), s37.UEContextReleaseCommandIEs().Cause().Info()}
	report := s37.BridgeUEContextReleaseCommandIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextReleaseCommand.protocolIEs", budget)
	BridgeWalkValidationUEContextReleaseCommand(v, &report, "UEContextReleaseCommand", true)
	return report, nil
}
func BridgeValidateUEContextReleaseCompleteBudget(v *s46.UEContextReleaseComplete, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextReleaseComplete")
	}
	rows := []s00.FieldInfo{s45.UEContextReleaseCompleteIEs().MMEUES1APID().Info(), s45.UEContextReleaseCompleteIEs().ENBUES1APID().Info(), s45.UEContextReleaseCompleteIEs().CriticalityDiagnostics().Info(), s45.UEContextReleaseCompleteIEs().UserLocationInformation().Info(), s45.UEContextReleaseCompleteIEs().InformationOnRecommendedCellsAndENBsForPaging().Info(), s45.UEContextReleaseCompleteIEs().CellIdentifierAndCELevelForCECapableUEs().Info(), s45.UEContextReleaseCompleteIEs().SecondaryRATDataUsageReportList().Info(), s45.UEContextReleaseCompleteIEs().TimeSinceSecondaryNodeRelease().Info()}
	report := s46.BridgeUEContextReleaseCompleteIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextReleaseComplete.protocolIEs", budget)
	BridgeWalkValidationUEContextReleaseComplete(v, &report, "UEContextReleaseComplete", true)
	return report, nil
}
func BridgeValidateTraceStartBudget(v *s49.TraceStart, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil TraceStart")
	}
	rows := []s00.FieldInfo{s49.TraceStartIEs().MMEUES1APID().Info(), s49.TraceStartIEs().ENBUES1APID().Info(), s49.TraceStartIEs().TraceActivation().Info()}
	report := s49.BridgeTraceStartIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "TraceStart.protocolIEs", budget)
	BridgeWalkValidationTraceStart(v, &report, "TraceStart", true)
	return report, nil
}
func BridgeValidateTraceFailureIndicationBudget(v *s35.TraceFailureIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil TraceFailureIndication")
	}
	rows := []s00.FieldInfo{s21.TraceFailureIndicationIEs().MMEUES1APID().Info(), s21.TraceFailureIndicationIEs().ENBUES1APID().Info(), s21.TraceFailureIndicationIEs().EUTRANTraceID().Info(), s21.TraceFailureIndicationIEs().Cause().Info()}
	report := s35.BridgeTraceFailureIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "TraceFailureIndication.protocolIEs", budget)
	BridgeWalkValidationTraceFailureIndication(v, &report, "TraceFailureIndication", true)
	return report, nil
}
func BridgeValidateENBConfigurationUpdateBudget(v *s43.ENBConfigurationUpdate, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBConfigurationUpdate")
	}
	rows := []s00.FieldInfo{s43.ENBConfigurationUpdateIEs().ENBname().Info(), s43.ENBConfigurationUpdateIEs().SupportedTAs().Info(), s43.ENBConfigurationUpdateIEs().CSGIdList().Info(), s43.ENBConfigurationUpdateIEs().DefaultPagingDRX().Info(), s43.ENBConfigurationUpdateIEs().NBIoTDefaultPagingDRX().Info(), s43.ENBConfigurationUpdateIEs().ConnectedengNBToAddList().Info(), s43.ENBConfigurationUpdateIEs().ConnectedengNBToRemoveList().Info()}
	report := s43.BridgeENBConfigurationUpdateIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBConfigurationUpdate.protocolIEs", budget)
	BridgeWalkValidationENBConfigurationUpdate(v, &report, "ENBConfigurationUpdate", true)
	return report, nil
}
func BridgeValidateMMEConfigurationUpdateBudget(v *s43.MMEConfigurationUpdate, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEConfigurationUpdate")
	}
	rows := []s00.FieldInfo{s43.MMEConfigurationUpdateIEs().MMEname().Info(), s43.MMEConfigurationUpdateIEs().ServedGUMMEIs().Info(), s43.MMEConfigurationUpdateIEs().RelativeMMECapacity().Info(), s43.MMEConfigurationUpdateIEs().ServedDCNs().Info()}
	report := s43.BridgeMMEConfigurationUpdateIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEConfigurationUpdate.protocolIEs", budget)
	BridgeWalkValidationMMEConfigurationUpdate(v, &report, "MMEConfigurationUpdate", true)
	return report, nil
}
func BridgeValidateLocationReportBudget(v *s33.LocationReport, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil LocationReport")
	}
	rows := []s00.FieldInfo{s32.LocationReportIEs().MMEUES1APID().Info(), s32.LocationReportIEs().ENBUES1APID().Info(), s32.LocationReportIEs().EUTRANCGI().Info(), s32.LocationReportIEs().TAI().Info(), s32.LocationReportIEs().RequestType().Info(), s32.LocationReportIEs().PSCellInformation().Info(), s32.LocationReportIEs().LTENTNTAIInformation().Info()}
	report := s33.BridgeLocationReportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "LocationReport.protocolIEs", budget)
	BridgeWalkValidationLocationReport(v, &report, "LocationReport", true)
	return report, nil
}
func BridgeValidateWriteReplaceWarningRequestBudget(v *WriteReplaceWarningRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil WriteReplaceWarningRequest")
	}
	rows := []s00.FieldInfo{s33.WriteReplaceWarningRequestIEs().MessageIdentifier().Info(), s33.WriteReplaceWarningRequestIEs().SerialNumber().Info(), s33.WriteReplaceWarningRequestIEs().WarningAreaList().Info(), s33.WriteReplaceWarningRequestIEs().RepetitionPeriod().Info(), s33.WriteReplaceWarningRequestIEs().ExtendedRepetitionPeriod().Info(), s33.WriteReplaceWarningRequestIEs().NumberofBroadcastRequest().Info(), s33.WriteReplaceWarningRequestIEs().WarningType().Info(), s33.WriteReplaceWarningRequestIEs().WarningSecurityInfo().Info(), s33.WriteReplaceWarningRequestIEs().DataCodingScheme().Info(), s33.WriteReplaceWarningRequestIEs().WarningMessageContents().Info(), s33.WriteReplaceWarningRequestIEs().ConcurrentWarningMessageIndicator().Info(), s33.WriteReplaceWarningRequestIEs().WarningAreaCoordinates().Info()}
	report := BridgeWriteReplaceWarningRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "WriteReplaceWarningRequest.protocolIEs", budget)
	BridgeWalkValidationWriteReplaceWarningRequest(v, &report, "WriteReplaceWarningRequest", true)
	return report, nil
}
func BridgeValidateWriteReplaceWarningResponseBudget(v *WriteReplaceWarningResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil WriteReplaceWarningResponse")
	}
	rows := []s00.FieldInfo{s32.WriteReplaceWarningResponseIEs().MessageIdentifier().Info(), s32.WriteReplaceWarningResponseIEs().SerialNumber().Info(), s32.WriteReplaceWarningResponseIEs().BroadcastCompletedAreaList().Info(), s32.WriteReplaceWarningResponseIEs().CriticalityDiagnostics().Info()}
	report := BridgeWriteReplaceWarningResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "WriteReplaceWarningResponse.protocolIEs", budget)
	BridgeWalkValidationWriteReplaceWarningResponse(v, &report, "WriteReplaceWarningResponse", true)
	return report, nil
}
func BridgeValidateENBDirectInformationTransferBudget(v *s34.ENBDirectInformationTransfer, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBDirectInformationTransfer")
	}
	rows := []s00.FieldInfo{s34.ENBDirectInformationTransferIEs().InterSystemInformationTransferTypeEDT().Info()}
	report := s34.BridgeENBDirectInformationTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBDirectInformationTransfer.protocolIEs", budget)
	BridgeWalkValidationENBDirectInformationTransfer(v, &report, "ENBDirectInformationTransfer", true)
	return report, nil
}
func BridgeValidateMMEDirectInformationTransferBudget(v *s34.MMEDirectInformationTransfer, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEDirectInformationTransfer")
	}
	rows := []s00.FieldInfo{s34.MMEDirectInformationTransferIEs().InterSystemInformationTransferTypeMDT().Info()}
	report := s34.BridgeMMEDirectInformationTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEDirectInformationTransfer.protocolIEs", budget)
	BridgeWalkValidationMMEDirectInformationTransfer(v, &report, "MMEDirectInformationTransfer", true)
	return report, nil
}
func BridgeValidateKillRequestBudget(v *s33.KillRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil KillRequest")
	}
	rows := []s00.FieldInfo{s33.KillRequestIEs().MessageIdentifier().Info(), s33.KillRequestIEs().SerialNumber().Info(), s33.KillRequestIEs().WarningAreaList().Info(), s33.KillRequestIEs().KillAllWarningMessages().Info()}
	report := s33.BridgeKillRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "KillRequest.protocolIEs", budget)
	BridgeWalkValidationKillRequest(v, &report, "KillRequest", true)
	return report, nil
}
func BridgeValidateKillResponseBudget(v *s33.KillResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil KillResponse")
	}
	rows := []s00.FieldInfo{s32.KillResponseIEs().MessageIdentifier().Info(), s32.KillResponseIEs().SerialNumber().Info(), s32.KillResponseIEs().BroadcastCancelledAreaList().Info(), s32.KillResponseIEs().CriticalityDiagnostics().Info()}
	report := s33.BridgeKillResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "KillResponse.protocolIEs", budget)
	BridgeWalkValidationKillResponse(v, &report, "KillResponse", true)
	return report, nil
}
func BridgeValidateUplinkUEAssociatedLPPaTransportBudget(v *s44.UplinkUEAssociatedLPPaTransport, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UplinkUEAssociatedLPPaTransport")
	}
	rows := []s00.FieldInfo{s12.UplinkUEAssociatedLPPaTransportIEs().MMEUES1APID().Info(), s12.UplinkUEAssociatedLPPaTransportIEs().ENBUES1APID().Info(), s12.UplinkUEAssociatedLPPaTransportIEs().RoutingID().Info(), s12.UplinkUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
	report := s44.BridgeUplinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UplinkUEAssociatedLPPaTransport.protocolIEs", budget)
	BridgeWalkValidationUplinkUEAssociatedLPPaTransport(v, &report, "UplinkUEAssociatedLPPaTransport", true)
	return report, nil
}
func BridgeValidateUplinkNonUEAssociatedLPPaTransportBudget(v *s44.UplinkNonUEAssociatedLPPaTransport, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UplinkNonUEAssociatedLPPaTransport")
	}
	rows := []s00.FieldInfo{s12.UplinkNonUEAssociatedLPPaTransportIEs().RoutingID().Info(), s12.UplinkNonUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
	report := s44.BridgeUplinkNonUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UplinkNonUEAssociatedLPPaTransport.protocolIEs", budget)
	BridgeWalkValidationUplinkNonUEAssociatedLPPaTransport(v, &report, "UplinkNonUEAssociatedLPPaTransport", true)
	return report, nil
}
func BridgeValidateUERadioCapabilityMatchRequestBudget(v *s36.UERadioCapabilityMatchRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UERadioCapabilityMatchRequest")
	}
	rows := []s00.FieldInfo{s12.UERadioCapabilityMatchRequestIEs().MMEUES1APID().Info(), s12.UERadioCapabilityMatchRequestIEs().ENBUES1APID().Info(), s12.UERadioCapabilityMatchRequestIEs().UERadioCapability().Info(), s12.UERadioCapabilityMatchRequestIEs().UERadioCapabilityID().Info()}
	report := s36.BridgeUERadioCapabilityMatchRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UERadioCapabilityMatchRequest.protocolIEs", budget)
	BridgeWalkValidationUERadioCapabilityMatchRequest(v, &report, "UERadioCapabilityMatchRequest", true)
	return report, nil
}
func BridgeValidateUERadioCapabilityMatchResponseBudget(v *s37.UERadioCapabilityMatchResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UERadioCapabilityMatchResponse")
	}
	rows := []s00.FieldInfo{s24.UERadioCapabilityMatchResponseIEs().MMEUES1APID().Info(), s24.UERadioCapabilityMatchResponseIEs().ENBUES1APID().Info(), s24.UERadioCapabilityMatchResponseIEs().VoiceSupportMatchIndicator().Info(), s24.UERadioCapabilityMatchResponseIEs().CriticalityDiagnostics().Info()}
	report := s37.BridgeUERadioCapabilityMatchResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UERadioCapabilityMatchResponse.protocolIEs", budget)
	BridgeWalkValidationUERadioCapabilityMatchResponse(v, &report, "UERadioCapabilityMatchResponse", true)
	return report, nil
}
func BridgeValidatePWSRestartIndicationBudget(v *s44.PWSRestartIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil PWSRestartIndication")
	}
	rows := []s00.FieldInfo{s44.PWSRestartIndicationIEs().ECGIListForRestart().Info(), s44.PWSRestartIndicationIEs().GlobalENBID().Info(), s44.PWSRestartIndicationIEs().TAIListForRestart().Info(), s44.PWSRestartIndicationIEs().EmergencyAreaIDListForRestart().Info()}
	report := s44.BridgePWSRestartIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "PWSRestartIndication.protocolIEs", budget)
	BridgeWalkValidationPWSRestartIndication(v, &report, "PWSRestartIndication", true)
	return report, nil
}
func BridgeValidateERABModificationIndicationBudget(v *s46.ERABModificationIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABModificationIndication")
	}
	rows := []s00.FieldInfo{s45.ERABModificationIndicationIEs().MMEUES1APID().Info(), s45.ERABModificationIndicationIEs().ENBUES1APID().Info(), s45.ERABModificationIndicationIEs().ERABToBeModifiedListBearerModInd().Info(), s45.ERABModificationIndicationIEs().ERABNotToBeModifiedListBearerModInd().Info(), s45.ERABModificationIndicationIEs().CSGMembershipInfo().Info(), s45.ERABModificationIndicationIEs().TunnelInformationForBBF().Info(), s45.ERABModificationIndicationIEs().SecondaryRATDataUsageReportList().Info(), s45.ERABModificationIndicationIEs().UserLocationInformation().Info()}
	report := s46.BridgeERABModificationIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABModificationIndication.protocolIEs", budget)
	BridgeWalkValidationERABModificationIndication(v, &report, "ERABModificationIndication", true)
	return report, nil
}
func BridgeValidateUEContextModificationIndicationBudget(v *s36.UEContextModificationIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextModificationIndication")
	}
	rows := []s00.FieldInfo{s21.UEContextModificationIndicationIEs().MMEUES1APID().Info(), s21.UEContextModificationIndicationIEs().ENBUES1APID().Info(), s21.UEContextModificationIndicationIEs().CSGMembershipInfo().Info()}
	report := s36.BridgeUEContextModificationIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextModificationIndication.protocolIEs", budget)
	BridgeWalkValidationUEContextModificationIndication(v, &report, "UEContextModificationIndication", true)
	return report, nil
}
func BridgeValidateUEContextModificationConfirmBudget(v *s36.UEContextModificationConfirm, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextModificationConfirm")
	}
	rows := []s00.FieldInfo{s23.UEContextModificationConfirmIEs().MMEUES1APID().Info(), s23.UEContextModificationConfirmIEs().ENBUES1APID().Info(), s23.UEContextModificationConfirmIEs().CSGMembershipStatus().Info(), s23.UEContextModificationConfirmIEs().CriticalityDiagnostics().Info()}
	report := s36.BridgeUEContextModificationConfirmIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextModificationConfirm.protocolIEs", budget)
	BridgeWalkValidationUEContextModificationConfirm(v, &report, "UEContextModificationConfirm", true)
	return report, nil
}
func BridgeValidateConnectionEstablishmentIndicationBudget(v *s31.ConnectionEstablishmentIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ConnectionEstablishmentIndication")
	}
	rows := []s00.FieldInfo{s31.ConnectionEstablishmentIndicationIEs().MMEUES1APID().Info(), s31.ConnectionEstablishmentIndicationIEs().ENBUES1APID().Info(), s31.ConnectionEstablishmentIndicationIEs().UERadioCapability().Info(), s31.ConnectionEstablishmentIndicationIEs().EnhancedCoverageRestricted().Info(), s31.ConnectionEstablishmentIndicationIEs().DLCPSecurityInformation().Info(), s31.ConnectionEstablishmentIndicationIEs().CEModeBRestricted().Info(), s31.ConnectionEstablishmentIndicationIEs().EndIndication().Info(), s31.ConnectionEstablishmentIndicationIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s31.ConnectionEstablishmentIndicationIEs().UELevelQoSParameters().Info(), s31.ConnectionEstablishmentIndicationIEs().UERadioCapabilityID().Info(), s31.ConnectionEstablishmentIndicationIEs().MaskedIMEISV().Info(), s31.ConnectionEstablishmentIndicationIEs().CoarseUELocation().Info()}
	report := s31.BridgeConnectionEstablishmentIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ConnectionEstablishmentIndication.protocolIEs", budget)
	BridgeWalkValidationConnectionEstablishmentIndication(v, &report, "ConnectionEstablishmentIndication", true)
	return report, nil
}
func BridgeValidateUEContextSuspendRequestBudget(v *s46.UEContextSuspendRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextSuspendRequest")
	}
	rows := []s00.FieldInfo{s46.UEContextSuspendRequestIEs().MMEUES1APID().Info(), s46.UEContextSuspendRequestIEs().ENBUES1APID().Info(), s46.UEContextSuspendRequestIEs().InformationOnRecommendedCellsAndENBsForPaging().Info(), s46.UEContextSuspendRequestIEs().CellIdentifierAndCELevelForCECapableUEs().Info(), s46.UEContextSuspendRequestIEs().SecondaryRATDataUsageReportList().Info(), s46.UEContextSuspendRequestIEs().UserLocationInformation().Info(), s46.UEContextSuspendRequestIEs().TimeSinceSecondaryNodeRelease().Info()}
	report := s46.BridgeUEContextSuspendRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextSuspendRequest.protocolIEs", budget)
	BridgeWalkValidationUEContextSuspendRequest(v, &report, "UEContextSuspendRequest", true)
	return report, nil
}
func BridgeValidateUEContextSuspendResponseBudget(v *s36.UEContextSuspendResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextSuspendResponse")
	}
	rows := []s00.FieldInfo{s28.UEContextSuspendResponseIEs().MMEUES1APID().Info(), s28.UEContextSuspendResponseIEs().ENBUES1APID().Info(), s28.UEContextSuspendResponseIEs().CriticalityDiagnostics().Info(), s28.UEContextSuspendResponseIEs().SecurityContext().Info()}
	report := s36.BridgeUEContextSuspendResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextSuspendResponse.protocolIEs", budget)
	BridgeWalkValidationUEContextSuspendResponse(v, &report, "UEContextSuspendResponse", true)
	return report, nil
}
func BridgeValidateUEContextResumeRequestBudget(v *s38.UEContextResumeRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextResumeRequest")
	}
	rows := []s00.FieldInfo{s38.UEContextResumeRequestIEs().MMEUES1APID().Info(), s38.UEContextResumeRequestIEs().ENBUES1APID().Info(), s38.UEContextResumeRequestIEs().ERABFailedToResumeListResumeReq().Info(), s38.UEContextResumeRequestIEs().RRCResumeCause().Info()}
	report := s38.BridgeUEContextResumeRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextResumeRequest.protocolIEs", budget)
	BridgeWalkValidationUEContextResumeRequest(v, &report, "UEContextResumeRequest", true)
	return report, nil
}
func BridgeValidateUEContextResumeResponseBudget(v *s38.UEContextResumeResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextResumeResponse")
	}
	rows := []s00.FieldInfo{s38.UEContextResumeResponseIEs().MMEUES1APID().Info(), s38.UEContextResumeResponseIEs().ENBUES1APID().Info(), s38.UEContextResumeResponseIEs().ERABFailedToResumeListResumeRes().Info(), s38.UEContextResumeResponseIEs().CriticalityDiagnostics().Info(), s38.UEContextResumeResponseIEs().SecurityContext().Info(), s38.UEContextResumeResponseIEs().PendingDataIndication().Info()}
	report := s39.BridgeUEContextResumeResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextResumeResponse.protocolIEs", budget)
	BridgeWalkValidationUEContextResumeResponse(v, &report, "UEContextResumeResponse", true)
	return report, nil
}
func BridgeValidateUEContextResumeFailureBudget(v *s36.UEContextResumeFailure, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextResumeFailure")
	}
	rows := []s00.FieldInfo{s23.UEContextResumeFailureIEs().MMEUES1APID().Info(), s23.UEContextResumeFailureIEs().ENBUES1APID().Info(), s23.UEContextResumeFailureIEs().Cause().Info(), s23.UEContextResumeFailureIEs().CriticalityDiagnostics().Info()}
	report := s36.BridgeUEContextResumeFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextResumeFailure.protocolIEs", budget)
	BridgeWalkValidationUEContextResumeFailure(v, &report, "UEContextResumeFailure", true)
	return report, nil
}
func BridgeValidateUEInformationTransferBudget(v *s36.UEInformationTransfer, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEInformationTransfer")
	}
	rows := []s00.FieldInfo{s31.UEInformationTransferIEs().STMSI().Info(), s31.UEInformationTransferIEs().UELevelQoSParameters().Info(), s31.UEInformationTransferIEs().UERadioCapability().Info(), s31.UEInformationTransferIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s31.UEInformationTransferIEs().PendingDataIndication().Info(), s31.UEInformationTransferIEs().MaskedIMEISV().Info()}
	report := s36.BridgeUEInformationTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEInformationTransfer.protocolIEs", budget)
	BridgeWalkValidationUEInformationTransfer(v, &report, "UEInformationTransfer", true)
	return report, nil
}
func BridgeValidateENBCPRelocationIndicationBudget(v *s37.ENBCPRelocationIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBCPRelocationIndication")
	}
	rows := []s00.FieldInfo{s37.ENBCPRelocationIndicationIEs().ENBUES1APID().Info(), s37.ENBCPRelocationIndicationIEs().STMSI().Info(), s37.ENBCPRelocationIndicationIEs().EUTRANCGI().Info(), s37.ENBCPRelocationIndicationIEs().TAI().Info(), s37.ENBCPRelocationIndicationIEs().ULCPSecurityInformation().Info(), s37.ENBCPRelocationIndicationIEs().LTENTNTAIInformation().Info()}
	report := s37.BridgeENBCPRelocationIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBCPRelocationIndication.protocolIEs", budget)
	BridgeWalkValidationENBCPRelocationIndication(v, &report, "ENBCPRelocationIndication", true)
	return report, nil
}
func BridgeValidateSecondaryRATDataUsageReportBudget(v *s46.SecondaryRATDataUsageReport, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil SecondaryRATDataUsageReport")
	}
	rows := []s00.FieldInfo{s45.SecondaryRATDataUsageReportIEs().MMEUES1APID().Info(), s45.SecondaryRATDataUsageReportIEs().ENBUES1APID().Info(), s45.SecondaryRATDataUsageReportIEs().SecondaryRATDataUsageReportList().Info(), s45.SecondaryRATDataUsageReportIEs().HandoverFlag().Info(), s45.SecondaryRATDataUsageReportIEs().UserLocationInformation().Info(), s45.SecondaryRATDataUsageReportIEs().TimeSinceSecondaryNodeRelease().Info()}
	report := s46.BridgeSecondaryRATDataUsageReportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "SecondaryRATDataUsageReport.protocolIEs", budget)
	BridgeWalkValidationSecondaryRATDataUsageReport(v, &report, "SecondaryRATDataUsageReport", true)
	return report, nil
}
func BridgeValidateUERadioCapabilityIDMappingRequestBudget(v *s36.UERadioCapabilityIDMappingRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UERadioCapabilityIDMappingRequest")
	}
	rows := []s00.FieldInfo{s12.UERadioCapabilityIDMappingRequestIEs().UERadioCapabilityID().Info()}
	report := s36.BridgeUERadioCapabilityIDMappingRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UERadioCapabilityIDMappingRequest.protocolIEs", budget)
	BridgeWalkValidationUERadioCapabilityIDMappingRequest(v, &report, "UERadioCapabilityIDMappingRequest", true)
	return report, nil
}
func BridgeValidateUERadioCapabilityIDMappingResponseBudget(v *s36.UERadioCapabilityIDMappingResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UERadioCapabilityIDMappingResponse")
	}
	rows := []s00.FieldInfo{s24.UERadioCapabilityIDMappingResponseIEs().UERadioCapabilityID().Info(), s24.UERadioCapabilityIDMappingResponseIEs().UERadioCapability().Info(), s24.UERadioCapabilityIDMappingResponseIEs().CriticalityDiagnostics().Info()}
	report := s36.BridgeUERadioCapabilityIDMappingResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UERadioCapabilityIDMappingResponse.protocolIEs", budget)
	BridgeWalkValidationUERadioCapabilityIDMappingResponse(v, &report, "UERadioCapabilityIDMappingResponse", true)
	return report, nil
}
func ValidateHandoverRequired(v *s34.HandoverRequired, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "HandoverRequired")
	}
	report, err := BridgeValidateHandoverRequiredBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s34.BridgeHandoverRequiredMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverRequired")
}
func ValidateHandoverRequest(v *s49.HandoverRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "HandoverRequest")
	}
	report, err := BridgeValidateHandoverRequestBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s49.BridgeHandoverRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverRequest")
}
func ValidateHandoverNotify(v *s35.HandoverNotify, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "HandoverNotify")
	}
	report, err := BridgeValidateHandoverNotifyBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s35.BridgeHandoverNotifyMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverNotify")
}
func ValidatePathSwitchRequest(v *s41.PathSwitchRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "PathSwitchRequest")
	}
	report, err := BridgeValidatePathSwitchRequestBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s41.BridgePathSwitchRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PathSwitchRequest")
}
func ValidatePathSwitchRequestAcknowledge(v *s47.PathSwitchRequestAcknowledge, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	report, err := BridgeValidatePathSwitchRequestAcknowledgeBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s47.BridgePathSwitchRequestAcknowledgeMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PathSwitchRequestAcknowledge")
}
func ValidateERABSetupRequest(v *s40.ERABSetupRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABSetupRequest")
	}
	report, err := BridgeValidateERABSetupRequestBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s40.BridgeERABSetupRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABSetupRequest")
}
func ValidateERABSetupResponse(v *s46.ERABSetupResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABSetupResponse")
	}
	report, err := BridgeValidateERABSetupResponseBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeERABSetupResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABSetupResponse")
}
func ValidateERABModifyRequest(v *s40.ERABModifyRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABModifyRequest")
	}
	report, err := BridgeValidateERABModifyRequestBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s40.BridgeERABModifyRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABModifyRequest")
}
func ValidateERABModifyResponse(v *s46.ERABModifyResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABModifyResponse")
	}
	report, err := BridgeValidateERABModifyResponseBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeERABModifyResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABModifyResponse")
}
func ValidateERABReleaseCommand(v *s39.ERABReleaseCommand, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABReleaseCommand")
	}
	report, err := BridgeValidateERABReleaseCommandBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s39.BridgeERABReleaseCommandMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABReleaseCommand")
}
func ValidateERABReleaseResponse(v *s46.ERABReleaseResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABReleaseResponse")
	}
	report, err := BridgeValidateERABReleaseResponseBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeERABReleaseResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABReleaseResponse")
}
func ValidateERABReleaseIndication(v *s46.ERABReleaseIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABReleaseIndication")
	}
	report, err := BridgeValidateERABReleaseIndicationBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeERABReleaseIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABReleaseIndication")
}
func ValidateInitialContextSetupRequest(v *s49.InitialContextSetupRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "InitialContextSetupRequest")
	}
	report, err := BridgeValidateInitialContextSetupRequestBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s49.BridgeInitialContextSetupRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "InitialContextSetupRequest")
}
func ValidatePaging(v *s49.Paging, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "Paging")
	}
	report, err := BridgeValidatePagingBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s49.BridgePagingMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "Paging")
}
func ValidateDownlinkNASTransport(v *s42.DownlinkNASTransport, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "DownlinkNASTransport")
	}
	report, err := BridgeValidateDownlinkNASTransportBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s42.BridgeDownlinkNASTransportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "DownlinkNASTransport")
}
func ValidateInitialUEMessage(v *s35.InitialUEMessage, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "InitialUEMessage")
	}
	report, err := BridgeValidateInitialUEMessageBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s35.BridgeInitialUEMessageMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "InitialUEMessage")
}
func ValidateUplinkNASTransport(v *s44.UplinkNASTransport, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UplinkNASTransport")
	}
	report, err := BridgeValidateUplinkNASTransportBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s44.BridgeUplinkNASTransportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UplinkNASTransport")
}
func ValidateReset(v *s36.Reset, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "Reset")
	}
	report, err := BridgeValidateResetBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeResetMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "Reset")
}
func ValidateResetAcknowledge(v *s44.ResetAcknowledge, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ResetAcknowledge")
	}
	report, err := BridgeValidateResetAcknowledgeBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s44.BridgeResetAcknowledgeMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ResetAcknowledge")
}
func ValidateS1SetupRequest(v *s44.S1SetupRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "S1SetupRequest")
	}
	report, err := BridgeValidateS1SetupRequestBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s44.BridgeS1SetupRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "S1SetupRequest")
}
func ValidateS1SetupResponse(v *s43.S1SetupResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "S1SetupResponse")
	}
	report, err := BridgeValidateS1SetupResponseBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s43.BridgeS1SetupResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "S1SetupResponse")
}
func ValidateUEContextReleaseRequest(v *s43.UEContextReleaseRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextReleaseRequest")
	}
	report, err := BridgeValidateUEContextReleaseRequestBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s43.BridgeUEContextReleaseRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextReleaseRequest")
}
func ValidateUplinkS1cdma2000tunnelling(v *s44.UplinkS1cdma2000tunnelling, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	report, err := BridgeValidateUplinkS1cdma2000tunnellingBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s44.BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
}
func ValidateUEContextModificationRequest(v *s47.UEContextModificationRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextModificationRequest")
	}
	report, err := BridgeValidateUEContextModificationRequestBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s47.BridgeUEContextModificationRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextModificationRequest")
}
func ValidateUEContextModificationResponse(v *s36.UEContextModificationResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextModificationResponse")
	}
	report, err := BridgeValidateUEContextModificationResponseBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeUEContextModificationResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextModificationResponse")
}
func ValidateUEContextModificationFailure(v *s36.UEContextModificationFailure, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextModificationFailure")
	}
	report, err := BridgeValidateUEContextModificationFailureBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeUEContextModificationFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextModificationFailure")
}
func ValidateUECapabilityInfoIndication(v *s36.UECapabilityInfoIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UECapabilityInfoIndication")
	}
	report, err := BridgeValidateUECapabilityInfoIndicationBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeUECapabilityInfoIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UECapabilityInfoIndication")
}
func ValidateUEContextReleaseCommand(v *s37.UEContextReleaseCommand, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextReleaseCommand")
	}
	report, err := BridgeValidateUEContextReleaseCommandBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s37.BridgeUEContextReleaseCommandMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextReleaseCommand")
}
func ValidateUEContextReleaseComplete(v *s46.UEContextReleaseComplete, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextReleaseComplete")
	}
	report, err := BridgeValidateUEContextReleaseCompleteBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeUEContextReleaseCompleteMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextReleaseComplete")
}
func ValidateTraceStart(v *s49.TraceStart, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "TraceStart")
	}
	report, err := BridgeValidateTraceStartBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s49.BridgeTraceStartMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "TraceStart")
}
func ValidateTraceFailureIndication(v *s35.TraceFailureIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "TraceFailureIndication")
	}
	report, err := BridgeValidateTraceFailureIndicationBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s35.BridgeTraceFailureIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "TraceFailureIndication")
}
func ValidateENBConfigurationUpdate(v *s43.ENBConfigurationUpdate, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ENBConfigurationUpdate")
	}
	report, err := BridgeValidateENBConfigurationUpdateBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s43.BridgeENBConfigurationUpdateMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBConfigurationUpdate")
}
func ValidateMMEConfigurationUpdate(v *s43.MMEConfigurationUpdate, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "MMEConfigurationUpdate")
	}
	report, err := BridgeValidateMMEConfigurationUpdateBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s43.BridgeMMEConfigurationUpdateMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEConfigurationUpdate")
}
func ValidateLocationReport(v *s33.LocationReport, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "LocationReport")
	}
	report, err := BridgeValidateLocationReportBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s33.BridgeLocationReportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "LocationReport")
}
func ValidateWriteReplaceWarningRequest(v *WriteReplaceWarningRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "WriteReplaceWarningRequest")
	}
	report, err := BridgeValidateWriteReplaceWarningRequestBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = v.marshalAPERBudget(budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "WriteReplaceWarningRequest")
}
func ValidateWriteReplaceWarningResponse(v *WriteReplaceWarningResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "WriteReplaceWarningResponse")
	}
	report, err := BridgeValidateWriteReplaceWarningResponseBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = v.marshalAPERBudget(budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "WriteReplaceWarningResponse")
}
func ValidateENBDirectInformationTransfer(v *s34.ENBDirectInformationTransfer, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ENBDirectInformationTransfer")
	}
	report, err := BridgeValidateENBDirectInformationTransferBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s34.BridgeENBDirectInformationTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBDirectInformationTransfer")
}
func ValidateMMEDirectInformationTransfer(v *s34.MMEDirectInformationTransfer, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "MMEDirectInformationTransfer")
	}
	report, err := BridgeValidateMMEDirectInformationTransferBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s34.BridgeMMEDirectInformationTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEDirectInformationTransfer")
}
func ValidateKillRequest(v *s33.KillRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "KillRequest")
	}
	report, err := BridgeValidateKillRequestBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s33.BridgeKillRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "KillRequest")
}
func ValidateKillResponse(v *s33.KillResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "KillResponse")
	}
	report, err := BridgeValidateKillResponseBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s33.BridgeKillResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "KillResponse")
}
func ValidateUplinkUEAssociatedLPPaTransport(v *s44.UplinkUEAssociatedLPPaTransport, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	report, err := BridgeValidateUplinkUEAssociatedLPPaTransportBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s44.BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
}
func ValidateUplinkNonUEAssociatedLPPaTransport(v *s44.UplinkNonUEAssociatedLPPaTransport, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	report, err := BridgeValidateUplinkNonUEAssociatedLPPaTransportBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s44.BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
}
func ValidateUERadioCapabilityMatchRequest(v *s36.UERadioCapabilityMatchRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UERadioCapabilityMatchRequest")
	}
	report, err := BridgeValidateUERadioCapabilityMatchRequestBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeUERadioCapabilityMatchRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UERadioCapabilityMatchRequest")
}
func ValidateUERadioCapabilityMatchResponse(v *s37.UERadioCapabilityMatchResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UERadioCapabilityMatchResponse")
	}
	report, err := BridgeValidateUERadioCapabilityMatchResponseBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s37.BridgeUERadioCapabilityMatchResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UERadioCapabilityMatchResponse")
}
func ValidatePWSRestartIndication(v *s44.PWSRestartIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "PWSRestartIndication")
	}
	report, err := BridgeValidatePWSRestartIndicationBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s44.BridgePWSRestartIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PWSRestartIndication")
}
func ValidateERABModificationIndication(v *s46.ERABModificationIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABModificationIndication")
	}
	report, err := BridgeValidateERABModificationIndicationBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeERABModificationIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABModificationIndication")
}
func ValidateUEContextModificationIndication(v *s36.UEContextModificationIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextModificationIndication")
	}
	report, err := BridgeValidateUEContextModificationIndicationBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeUEContextModificationIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextModificationIndication")
}
func ValidateUEContextModificationConfirm(v *s36.UEContextModificationConfirm, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextModificationConfirm")
	}
	report, err := BridgeValidateUEContextModificationConfirmBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeUEContextModificationConfirmMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextModificationConfirm")
}
func ValidateConnectionEstablishmentIndication(v *s31.ConnectionEstablishmentIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	report, err := BridgeValidateConnectionEstablishmentIndicationBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s31.BridgeConnectionEstablishmentIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ConnectionEstablishmentIndication")
}
func ValidateUEContextSuspendRequest(v *s46.UEContextSuspendRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextSuspendRequest")
	}
	report, err := BridgeValidateUEContextSuspendRequestBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeUEContextSuspendRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextSuspendRequest")
}
func ValidateUEContextSuspendResponse(v *s36.UEContextSuspendResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextSuspendResponse")
	}
	report, err := BridgeValidateUEContextSuspendResponseBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeUEContextSuspendResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextSuspendResponse")
}
func ValidateUEContextResumeRequest(v *s38.UEContextResumeRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextResumeRequest")
	}
	report, err := BridgeValidateUEContextResumeRequestBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s38.BridgeUEContextResumeRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextResumeRequest")
}
func ValidateUEContextResumeResponse(v *s38.UEContextResumeResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextResumeResponse")
	}
	report, err := BridgeValidateUEContextResumeResponseBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s38.BridgeUEContextResumeResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextResumeResponse")
}
func ValidateUEContextResumeFailure(v *s36.UEContextResumeFailure, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextResumeFailure")
	}
	report, err := BridgeValidateUEContextResumeFailureBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeUEContextResumeFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextResumeFailure")
}
func ValidateUEInformationTransfer(v *s36.UEInformationTransfer, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEInformationTransfer")
	}
	report, err := BridgeValidateUEInformationTransferBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeUEInformationTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEInformationTransfer")
}
func ValidateENBCPRelocationIndication(v *s37.ENBCPRelocationIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	report, err := BridgeValidateENBCPRelocationIndicationBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s37.BridgeENBCPRelocationIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBCPRelocationIndication")
}
func ValidateSecondaryRATDataUsageReport(v *s46.SecondaryRATDataUsageReport, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	report, err := BridgeValidateSecondaryRATDataUsageReportBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeSecondaryRATDataUsageReportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "SecondaryRATDataUsageReport")
}
func ValidateUERadioCapabilityIDMappingRequest(v *s36.UERadioCapabilityIDMappingRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	report, err := BridgeValidateUERadioCapabilityIDMappingRequestBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
}
func ValidateUERadioCapabilityIDMappingResponse(v *s36.UERadioCapabilityIDMappingResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	report, err := BridgeValidateUERadioCapabilityIDMappingResponseBudget(v, budget)
	if err == nil && !s47.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
}
func BridgeWalkValidationAreaScopeOfMDT(v *s32.AreaScopeOfMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.AreaScopeOfMDTChoiceCellBased && v.CellBased != nil {
		s49.BridgeWalkValidationCellBasedMDT(v.CellBased, report, path+".cellBased", false)
	}
	if v.Choice == s00.AreaScopeOfMDTChoiceTABased && v.TABased != nil {
		BridgeWalkValidationTABasedMDT(v.TABased, report, path+".tABased", false)
	}
	if v.Choice == s00.AreaScopeOfMDTChoiceTAIBased && v.TAIBased != nil {
		BridgeWalkValidationTAIBasedMDT(v.TAIBased, report, path+".tAIBased", false)
	}
}
func BridgeWalkValidationAreaScopeOfQMC(v *s32.AreaScopeOfQMC, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.AreaScopeOfQMCChoiceCellBased && v.CellBased != nil {
		s49.BridgeWalkValidationCellBasedQMC(v.CellBased, report, path+".cellBased", false)
	}
	if v.Choice == s00.AreaScopeOfQMCChoiceTABased && v.TABased != nil {
		BridgeWalkValidationTABasedQMC(v.TABased, report, path+".tABased", false)
	}
	if v.Choice == s00.AreaScopeOfQMCChoiceTAIBased && v.TAIBased != nil {
		BridgeWalkValidationTAIBasedQMC(v.TAIBased, report, path+".tAIBased", false)
	}
	if v.Choice == s00.AreaScopeOfQMCChoicePLMNAreaBased && v.PLMNAreaBased != nil {
		s49.BridgeWalkValidationPLMNAreaBasedQMC(v.PLMNAreaBased, report, path+".pLMNAreaBased", false)
	}
}
func BridgeWalkValidationBroadcastCancelledAreaList(v *s32.BroadcastCancelledAreaList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.BroadcastCancelledAreaListChoiceCellIDCancelled && v.CellIDCancelled != nil {
		s49.BridgeWalkValidationCellIDCancelled(&v.CellIDCancelled, report, path+".cellID-Cancelled", false)
	}
	if v.Choice == s00.BroadcastCancelledAreaListChoiceTAICancelled && v.TAICancelled != nil {
		BridgeWalkValidationTAICancelled(&v.TAICancelled, report, path+".tAI-Cancelled", false)
	}
	if v.Choice == s00.BroadcastCancelledAreaListChoiceEmergencyAreaIDCancelled && v.EmergencyAreaIDCancelled != nil {
		s49.BridgeWalkValidationEmergencyAreaIDCancelled(&v.EmergencyAreaIDCancelled, report, path+".emergencyAreaID-Cancelled", false)
	}
}
func BridgeWalkValidationBroadcastCompletedAreaList(v *s32.BroadcastCompletedAreaList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.BroadcastCompletedAreaListChoiceCellIDBroadcast && v.CellIDBroadcast != nil {
		s49.BridgeWalkValidationCellIDBroadcast(&v.CellIDBroadcast, report, path+".cellID-Broadcast", false)
	}
	if v.Choice == s00.BroadcastCompletedAreaListChoiceTAIBroadcast && v.TAIBroadcast != nil {
		BridgeWalkValidationTAIBroadcast(&v.TAIBroadcast, report, path+".tAI-Broadcast", false)
	}
	if v.Choice == s00.BroadcastCompletedAreaListChoiceEmergencyAreaIDBroadcast && v.EmergencyAreaIDBroadcast != nil {
		s49.BridgeWalkValidationEmergencyAreaIDBroadcast(&v.EmergencyAreaIDBroadcast, report, path+".emergencyAreaID-Broadcast", false)
	}
}
func BridgeWalkValidationConnectedengNBItem(v *s31.ConnectedengNBItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationSupportedTAs(&v.SupportedTAs, report, path+".supportedTAs", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s27.BridgeConnectedengNBItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationConnectedengNBList(v *s31.ConnectedengNBList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationConnectedengNBItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationConnectionEstablishmentIndication(v *s31.ConnectionEstablishmentIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s31.ConnectionEstablishmentIndicationIEs().MMEUES1APID().Info(), s31.ConnectionEstablishmentIndicationIEs().ENBUES1APID().Info(), s31.ConnectionEstablishmentIndicationIEs().UERadioCapability().Info(), s31.ConnectionEstablishmentIndicationIEs().EnhancedCoverageRestricted().Info(), s31.ConnectionEstablishmentIndicationIEs().DLCPSecurityInformation().Info(), s31.ConnectionEstablishmentIndicationIEs().CEModeBRestricted().Info(), s31.ConnectionEstablishmentIndicationIEs().EndIndication().Info(), s31.ConnectionEstablishmentIndicationIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s31.ConnectionEstablishmentIndicationIEs().UELevelQoSParameters().Info(), s31.ConnectionEstablishmentIndicationIEs().UERadioCapabilityID().Info(), s31.ConnectionEstablishmentIndicationIEs().MaskedIMEISV().Info(), s31.ConnectionEstablishmentIndicationIEs().CoarseUELocation().Info()}
			s25.BridgeMergeNestedValidation(report, s31.BridgeConnectionEstablishmentIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(253):
				if value, ok := fields[i].Value.AsDLCPSecurityInformation(); ok {
					s49.BridgeWalkValidationDLCPSecurityInformation(value, report, fmt.Sprintf("%s[%d]{id=253}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(252):
				if value, ok := fields[i].Value.AsUELevelQoSParameters(); ok {
					s49.BridgeWalkValidationERABLevelQoSParameters(value, report, fmt.Sprintf("%s[%d]{id=252}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationDownlinkNASTransport(v *s42.DownlinkNASTransport, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s42.DownlinkNASTransportIEs().MMEUES1APID().Info(), s42.DownlinkNASTransportIEs().ENBUES1APID().Info(), s42.DownlinkNASTransportIEs().NASPDU().Info(), s42.DownlinkNASTransportIEs().HandoverRestrictionList().Info(), s42.DownlinkNASTransportIEs().SubscriberProfileIDforRFP().Info(), s42.DownlinkNASTransportIEs().SRVCCOperationPossible().Info(), s42.DownlinkNASTransportIEs().UERadioCapability().Info(), s42.DownlinkNASTransportIEs().DLNASPDUDeliveryAckRequest().Info(), s42.DownlinkNASTransportIEs().EnhancedCoverageRestricted().Info(), s42.DownlinkNASTransportIEs().NRUESecurityCapabilities().Info(), s42.DownlinkNASTransportIEs().CEModeBRestricted().Info(), s42.DownlinkNASTransportIEs().UECapabilityInfoRequest().Info(), s42.DownlinkNASTransportIEs().EndIndication().Info(), s42.DownlinkNASTransportIEs().PendingDataIndication().Info(), s42.DownlinkNASTransportIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s42.DownlinkNASTransportIEs().AdditionalRRMPriorityIndex().Info(), s42.DownlinkNASTransportIEs().UERadioCapabilityID().Info(), s42.DownlinkNASTransportIEs().MaskedIMEISV().Info(), s42.DownlinkNASTransportIEs().CoarseUELocation().Info()}
			s25.BridgeMergeNestedValidation(report, s42.BridgeDownlinkNASTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(41):
				if value, ok := fields[i].Value.AsHandoverRestrictionList(); ok {
					s49.BridgeWalkValidationHandoverRestrictionList(value, report, fmt.Sprintf("%s[%d]{id=41}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(269):
				if value, ok := fields[i].Value.AsNRUESecurityCapabilities(); ok {
					s49.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBCPRelocationIndication(v *s37.ENBCPRelocationIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s37.ENBCPRelocationIndicationIEs().ENBUES1APID().Info(), s37.ENBCPRelocationIndicationIEs().STMSI().Info(), s37.ENBCPRelocationIndicationIEs().EUTRANCGI().Info(), s37.ENBCPRelocationIndicationIEs().TAI().Info(), s37.ENBCPRelocationIndicationIEs().ULCPSecurityInformation().Info(), s37.ENBCPRelocationIndicationIEs().LTENTNTAIInformation().Info()}
			s25.BridgeMergeNestedValidation(report, s37.BridgeENBCPRelocationIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(96):
				if value, ok := fields[i].Value.AsSTMSI(); ok {
					s49.BridgeWalkValidationSTMSI(value, report, fmt.Sprintf("%s[%d]{id=96}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					s49.BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(254):
				if value, ok := fields[i].Value.AsULCPSecurityInformation(); ok {
					BridgeWalkValidationULCPSecurityInformation(value, report, fmt.Sprintf("%s[%d]{id=254}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBConfigurationUpdate(v *s43.ENBConfigurationUpdate, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s43.ENBConfigurationUpdateIEs().ENBname().Info(), s43.ENBConfigurationUpdateIEs().SupportedTAs().Info(), s43.ENBConfigurationUpdateIEs().CSGIdList().Info(), s43.ENBConfigurationUpdateIEs().DefaultPagingDRX().Info(), s43.ENBConfigurationUpdateIEs().NBIoTDefaultPagingDRX().Info(), s43.ENBConfigurationUpdateIEs().ConnectedengNBToAddList().Info(), s43.ENBConfigurationUpdateIEs().ConnectedengNBToRemoveList().Info()}
			s25.BridgeMergeNestedValidation(report, s43.BridgeENBConfigurationUpdateIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(64):
				if value, ok := fields[i].Value.AsSupportedTAs(); ok {
					BridgeWalkValidationSupportedTAs(value, report, fmt.Sprintf("%s[%d]{id=64}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(128):
				if value, ok := fields[i].Value.AsCSGIdList(); ok {
					s49.BridgeWalkValidationCSGIdList(value, report, fmt.Sprintf("%s[%d]{id=128}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(292):
				if value, ok := fields[i].Value.AsConnectedengNBToAddList(); ok {
					BridgeWalkValidationConnectedengNBList(value, report, fmt.Sprintf("%s[%d]{id=292}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(293):
				if value, ok := fields[i].Value.AsConnectedengNBToRemoveList(); ok {
					BridgeWalkValidationConnectedengNBList(value, report, fmt.Sprintf("%s[%d]{id=293}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBDirectInformationTransfer(v *s34.ENBDirectInformationTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s34.ENBDirectInformationTransferIEs().InterSystemInformationTransferTypeEDT().Info()}
			s25.BridgeMergeNestedValidation(report, s34.BridgeENBDirectInformationTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(121):
				if value, ok := fields[i].Value.AsInterSystemInformationTransferTypeEDT(); ok {
					BridgeWalkValidationInterSystemInformationTransferType(value, report, fmt.Sprintf("%s[%d]{id=121}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENDCSONTransferType(v *s31.ENDCSONTransferType, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.ENDCSONTransferTypeChoiceRequest && v.Request != nil {
		BridgeWalkValidationENDCTransferTypeRequest(v.Request, report, path+".request", false)
	}
	if v.Choice == s00.ENDCSONTransferTypeChoiceReply && v.Reply != nil {
		BridgeWalkValidationENDCTransferTypeReply(v.Reply, report, path+".reply", false)
	}
}
func BridgeWalkValidationENDCSONeNBIdentification(v *s31.ENDCSONeNBIdentification, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s49.BridgeWalkValidationGlobalENBID(&v.GlobaleNBID, report, path+".globaleNBID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationTAI(&v.SelectedTAI, report, path+".selectedTAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s27.BridgeENDCSONeNBIdentificationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENDCSONengNBIdentification(v *s31.ENDCSONengNBIdentification, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s49.BridgeWalkValidationGlobalEnGNBID(&v.GlobalengNBID, report, path+".globalengNBID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationTAI(&v.SelectedTAI, report, path+".selectedTAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s27.BridgeENDCSONengNBIdentificationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENDCTransferTypeReply(v *s31.ENDCTransferTypeReply, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationENDCSONengNBIdentification(&v.SourceengNB, report, path+".sourceengNB", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationENDCSONeNBIdentification(&v.TargeteNB, report, path+".targeteNB", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s27.BridgeENDCTransferTypeReplyExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENDCTransferTypeRequest(v *s31.ENDCTransferTypeRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationENDCSONeNBIdentification(&v.SourceeNB, report, path+".sourceeNB", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationENDCSONengNBIdentification(&v.TargetengNB, report, path+".targetengNB", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.TargeteNB != nil {
		BridgeWalkValidationENDCSONeNBIdentification(v.TargeteNB, report, path+".targeteNB", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.AssociatedTAI != nil {
		BridgeWalkValidationTAI(v.AssociatedTAI, report, path+".associatedTAI", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.Broadcast5GSTAI != nil {
		s49.BridgeWalkValidationFiveGSTAI(v.Broadcast5GSTAI, report, path+".broadcast5GSTAI", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s27.BridgeENDCTransferTypeRequestExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABModificationIndication(v *s46.ERABModificationIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s45.ERABModificationIndicationIEs().MMEUES1APID().Info(), s45.ERABModificationIndicationIEs().ENBUES1APID().Info(), s45.ERABModificationIndicationIEs().ERABToBeModifiedListBearerModInd().Info(), s45.ERABModificationIndicationIEs().ERABNotToBeModifiedListBearerModInd().Info(), s45.ERABModificationIndicationIEs().CSGMembershipInfo().Info(), s45.ERABModificationIndicationIEs().TunnelInformationForBBF().Info(), s45.ERABModificationIndicationIEs().SecondaryRATDataUsageReportList().Info(), s45.ERABModificationIndicationIEs().UserLocationInformation().Info()}
			s25.BridgeMergeNestedValidation(report, s46.BridgeERABModificationIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(199):
				if value, ok := fields[i].Value.AsERABToBeModifiedListBearerModInd(); ok {
					s49.BridgeWalkValidationERABToBeModifiedListBearerModInd(value, report, fmt.Sprintf("%s[%d]{id=199}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(201):
				if value, ok := fields[i].Value.AsERABNotToBeModifiedListBearerModInd(); ok {
					s49.BridgeWalkValidationERABNotToBeModifiedListBearerModInd(value, report, fmt.Sprintf("%s[%d]{id=201}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(226):
				if value, ok := fields[i].Value.AsCSGMembershipInfo(); ok {
					s49.BridgeWalkValidationCSGMembershipInfo(value, report, fmt.Sprintf("%s[%d]{id=226}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(176):
				if value, ok := fields[i].Value.AsTunnelInformationForBBF(); ok {
					BridgeWalkValidationTunnelInformation(value, report, fmt.Sprintf("%s[%d]{id=176}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s49.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABModifyRequest(v *s40.ERABModifyRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s40.ERABModifyRequestIEs().MMEUES1APID().Info(), s40.ERABModifyRequestIEs().ENBUES1APID().Info(), s40.ERABModifyRequestIEs().UEaggregateMaximumBitrate().Info(), s40.ERABModifyRequestIEs().ERABToBeModifiedListBearerModReq().Info(), s40.ERABModifyRequestIEs().SecondaryRATDataUsageRequest().Info()}
			s25.BridgeMergeNestedValidation(report, s40.BridgeERABModifyRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(30):
				if value, ok := fields[i].Value.AsERABToBeModifiedListBearerModReq(); ok {
					BridgeWalkValidationERABToBeModifiedListBearerModReq(value, report, fmt.Sprintf("%s[%d]{id=30}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABModifyResponse(v *s46.ERABModifyResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s45.ERABModifyResponseIEs().MMEUES1APID().Info(), s45.ERABModifyResponseIEs().ENBUES1APID().Info(), s45.ERABModifyResponseIEs().ERABModifyListBearerModRes().Info(), s45.ERABModifyResponseIEs().ERABFailedToModifyList().Info(), s45.ERABModifyResponseIEs().CriticalityDiagnostics().Info(), s45.ERABModifyResponseIEs().SecondaryRATDataUsageReportList().Info(), s45.ERABModifyResponseIEs().UserLocationInformation().Info()}
			s25.BridgeMergeNestedValidation(report, s46.BridgeERABModifyResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(31):
				if value, ok := fields[i].Value.AsERABModifyListBearerModRes(); ok {
					s49.BridgeWalkValidationERABModifyListBearerModRes(value, report, fmt.Sprintf("%s[%d]{id=31}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(32):
				if value, ok := fields[i].Value.AsERABFailedToModifyList(); ok {
					s49.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=32}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s49.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABReleaseCommand(v *s39.ERABReleaseCommand, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s39.ERABReleaseCommandIEs().MMEUES1APID().Info(), s39.ERABReleaseCommandIEs().ENBUES1APID().Info(), s39.ERABReleaseCommandIEs().UEaggregateMaximumBitrate().Info(), s39.ERABReleaseCommandIEs().ERABToBeReleasedList().Info(), s39.ERABReleaseCommandIEs().NASPDU().Info()}
			s25.BridgeMergeNestedValidation(report, s39.BridgeERABReleaseCommandIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(33):
				if value, ok := fields[i].Value.AsERABToBeReleasedList(); ok {
					s49.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=33}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABReleaseIndication(v *s46.ERABReleaseIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s45.ERABReleaseIndicationIEs().MMEUES1APID().Info(), s45.ERABReleaseIndicationIEs().ENBUES1APID().Info(), s45.ERABReleaseIndicationIEs().ERABReleasedList().Info(), s45.ERABReleaseIndicationIEs().UserLocationInformation().Info(), s45.ERABReleaseIndicationIEs().SecondaryRATDataUsageReportList().Info()}
			s25.BridgeMergeNestedValidation(report, s46.BridgeERABReleaseIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(110):
				if value, ok := fields[i].Value.AsERABReleasedList(); ok {
					s49.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=110}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s49.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABReleaseResponse(v *s46.ERABReleaseResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s45.ERABReleaseResponseIEs().MMEUES1APID().Info(), s45.ERABReleaseResponseIEs().ENBUES1APID().Info(), s45.ERABReleaseResponseIEs().ERABReleaseListBearerRelComp().Info(), s45.ERABReleaseResponseIEs().ERABFailedToReleaseList().Info(), s45.ERABReleaseResponseIEs().CriticalityDiagnostics().Info(), s45.ERABReleaseResponseIEs().UserLocationInformation().Info(), s45.ERABReleaseResponseIEs().SecondaryRATDataUsageReportList().Info()}
			s25.BridgeMergeNestedValidation(report, s46.BridgeERABReleaseResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(69):
				if value, ok := fields[i].Value.AsERABReleaseListBearerRelComp(); ok {
					s49.BridgeWalkValidationERABReleaseListBearerRelComp(value, report, fmt.Sprintf("%s[%d]{id=69}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(34):
				if value, ok := fields[i].Value.AsERABFailedToReleaseList(); ok {
					s49.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=34}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s49.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABSecurityResultItem(v *s30.ERABSecurityResultItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationSecurityResult(&v.SecurityResult, report, path+".securityResult", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s27.BridgeERABSecurityResultItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABSecurityResultList(v *s30.ERABSecurityResultList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s30.ERABSecurityResultListIEs().ERABSecurityResultItem().Info()}
		s25.BridgeMergeNestedValidation(report, s30.BridgeERABSecurityResultListIEValueValidateS1APIEContainer(s30.ERABSecurityResultListIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s30.ERABSecurityResultListIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(334):
				if value, ok := fields[i].Value.AsERABSecurityResultItem(); ok {
					BridgeWalkValidationERABSecurityResultItem(value, report, fmt.Sprintf("%s[%d]{id=334}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABSetupRequest(v *s40.ERABSetupRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s40.ERABSetupRequestIEs().MMEUES1APID().Info(), s40.ERABSetupRequestIEs().ENBUES1APID().Info(), s40.ERABSetupRequestIEs().UEaggregateMaximumBitrate().Info(), s40.ERABSetupRequestIEs().ERABToBeSetupListBearerSUReq().Info()}
			s25.BridgeMergeNestedValidation(report, s40.BridgeERABSetupRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(16):
				if value, ok := fields[i].Value.AsERABToBeSetupListBearerSUReq(); ok {
					BridgeWalkValidationERABToBeSetupListBearerSUReq(value, report, fmt.Sprintf("%s[%d]{id=16}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABSetupResponse(v *s46.ERABSetupResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s45.ERABSetupResponseIEs().MMEUES1APID().Info(), s45.ERABSetupResponseIEs().ENBUES1APID().Info(), s45.ERABSetupResponseIEs().ERABSetupListBearerSURes().Info(), s45.ERABSetupResponseIEs().ERABFailedToSetupListBearerSURes().Info(), s45.ERABSetupResponseIEs().CriticalityDiagnostics().Info(), s45.ERABSetupResponseIEs().UserLocationInformation().Info()}
			s25.BridgeMergeNestedValidation(report, s46.BridgeERABSetupResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(28):
				if value, ok := fields[i].Value.AsERABSetupListBearerSURes(); ok {
					s49.BridgeWalkValidationERABSetupListBearerSURes(value, report, fmt.Sprintf("%s[%d]{id=28}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(29):
				if value, ok := fields[i].Value.AsERABFailedToSetupListBearerSURes(); ok {
					s49.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=29}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeModifiedItemBearerModReq(v *s25.ERABToBeModifiedItemBearerModReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s49.BridgeWalkValidationERABLevelQoSParameters(&v.ERABLevelQoSParameters, report, path+".e-RABLevelQoSParameters", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s21.ERABToBeModifyItemBearerModReqExtIEs().TransportInformation().Info())}
				s25.BridgeMergeNestedValidation(report, s27.BridgeERABToBeModifyItemBearerModReqExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(185):
					if value, ok := fields[i].ExtensionValue.AsTransportInformation(); ok {
						BridgeWalkValidationTransportInformation(value, report, fmt.Sprintf("%s[%d]{id=185}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeModifiedListBearerModReq(v *s25.ERABToBeModifiedListBearerModReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s25.ERABToBeModifiedItemBearerModReqIEs().ERABToBeModifiedItemBearerModReq().Info()}
		s25.BridgeMergeNestedValidation(report, s27.BridgeERABToBeModifiedItemBearerModReqIEValueValidateS1APIEContainer(s25.ERABToBeModifiedItemBearerModReqIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s25.ERABToBeModifiedItemBearerModReqIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(36):
				if value, ok := fields[i].Value.AsERABToBeModifiedItemBearerModReq(); ok {
					BridgeWalkValidationERABToBeModifiedItemBearerModReq(value, report, fmt.Sprintf("%s[%d]{id=36}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeSetupItemCtxtSUReq(v *s29.ERABToBeSetupItemCtxtSUReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s49.BridgeWalkValidationERABLevelQoSParameters(&v.ERABlevelQoSParameters, report, path+".e-RABlevelQoSParameters", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s29.ERABToBeSetupItemCtxtSUReqExtIEs().CorrelationID().Info()), s00.FieldInfo(s29.ERABToBeSetupItemCtxtSUReqExtIEs().SIPTOCorrelationID().Info()), s00.FieldInfo(s29.ERABToBeSetupItemCtxtSUReqExtIEs().BearerType().Info()), s00.FieldInfo(s29.ERABToBeSetupItemCtxtSUReqExtIEs().EthernetType().Info()), s00.FieldInfo(s29.ERABToBeSetupItemCtxtSUReqExtIEs().SecurityIndication().Info())}
				s25.BridgeMergeNestedValidation(report, s29.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(332):
					if value, ok := fields[i].ExtensionValue.AsSecurityIndication(); ok {
						s49.BridgeWalkValidationSecurityIndication(value, report, fmt.Sprintf("%s[%d]{id=332}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeSetupItemHOReq(v *s29.ERABToBeSetupItemHOReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s49.BridgeWalkValidationERABLevelQoSParameters(&v.ERABlevelQosParameters, report, path+".e-RABlevelQosParameters", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s29.ERABToBeSetupItemHOReqExtIEs().DataForwardingNotPossible().Info()), s00.FieldInfo(s29.ERABToBeSetupItemHOReqExtIEs().BearerType().Info()), s00.FieldInfo(s29.ERABToBeSetupItemHOReqExtIEs().EthernetType().Info()), s00.FieldInfo(s29.ERABToBeSetupItemHOReqExtIEs().SecurityIndication().Info())}
				s25.BridgeMergeNestedValidation(report, s30.BridgeERABToBeSetupItemHOReqExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(332):
					if value, ok := fields[i].ExtensionValue.AsSecurityIndication(); ok {
						s49.BridgeWalkValidationSecurityIndication(value, report, fmt.Sprintf("%s[%d]{id=332}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeSetupListBearerSUReq(v *s29.ERABToBeSetupListBearerSUReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s29.ERABToBeSetupItemBearerSUReqIEs().ERABToBeSetupItemBearerSUReq().Info()}
		s25.BridgeMergeNestedValidation(report, s29.BridgeERABToBeSetupItemBearerSUReqIEValueValidateS1APIEContainer(s29.ERABToBeSetupItemBearerSUReqIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s29.ERABToBeSetupItemBearerSUReqIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(17):
				if value, ok := fields[i].Value.AsERABToBeSetupItemBearerSUReq(); ok {
					s49.BridgeWalkValidationERABToBeSetupItemBearerSUReq(value, report, fmt.Sprintf("%s[%d]{id=17}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeSetupListCtxtSUReq(v *s29.ERABToBeSetupListCtxtSUReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s29.ERABToBeSetupItemCtxtSUReqIEs().ERABToBeSetupItemCtxtSUReq().Info()}
		s25.BridgeMergeNestedValidation(report, s29.BridgeERABToBeSetupItemCtxtSUReqIEValueValidateS1APIEContainer(s29.ERABToBeSetupItemCtxtSUReqIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s29.ERABToBeSetupItemCtxtSUReqIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(52):
				if value, ok := fields[i].Value.AsERABToBeSetupItemCtxtSUReq(); ok {
					BridgeWalkValidationERABToBeSetupItemCtxtSUReq(value, report, fmt.Sprintf("%s[%d]{id=52}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeSetupListHOReq(v *s30.ERABToBeSetupListHOReq, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s30.ERABToBeSetupItemHOReqIEs().ERABToBeSetupItemHOReq().Info()}
		s25.BridgeMergeNestedValidation(report, s30.BridgeERABToBeSetupItemHOReqIEValueValidateS1APIEContainer(s30.ERABToBeSetupItemHOReqIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s30.ERABToBeSetupItemHOReqIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(27):
				if value, ok := fields[i].Value.AsERABToBeSetupItemHOReq(); ok {
					BridgeWalkValidationERABToBeSetupItemHOReq(value, report, fmt.Sprintf("%s[%d]{id=27}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeSwitchedDLItem(v *s30.ERABToBeSwitchedDLItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s29.ERABToBeSwitchedDLItemExtIEs().SecurityIndication().Info())}
				s25.BridgeMergeNestedValidation(report, s30.BridgeERABToBeSwitchedDLItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(332):
					if value, ok := fields[i].ExtensionValue.AsSecurityIndication(); ok {
						s49.BridgeWalkValidationSecurityIndication(value, report, fmt.Sprintf("%s[%d]{id=332}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeSwitchedDLList(v *s30.ERABToBeSwitchedDLList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s30.ERABToBeSwitchedDLItemIEs().ERABToBeSwitchedDLItem().Info()}
		s25.BridgeMergeNestedValidation(report, s30.BridgeERABToBeSwitchedDLItemIEValueValidateS1APIEContainer(s30.ERABToBeSwitchedDLItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s30.ERABToBeSwitchedDLItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(23):
				if value, ok := fields[i].Value.AsERABToBeSwitchedDLItem(); ok {
					BridgeWalkValidationERABToBeSwitchedDLItem(value, report, fmt.Sprintf("%s[%d]{id=23}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeUpdatedItem(v *s29.ERABToBeUpdatedItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.SecurityIndication != nil {
		s49.BridgeWalkValidationSecurityIndication(v.SecurityIndication, report, path+".securityIndication", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s27.BridgeERABToBeUpdatedItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeUpdatedList(v *s29.ERABToBeUpdatedList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s29.ERABToBeUpdatedItemIEs().ERABToBeUpdatedItem().Info()}
		s25.BridgeMergeNestedValidation(report, s30.BridgeERABToBeUpdatedItemIEValueValidateS1APIEContainer(s29.ERABToBeUpdatedItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s29.ERABToBeUpdatedItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(342):
				if value, ok := fields[i].Value.AsERABToBeUpdatedItem(); ok {
					BridgeWalkValidationERABToBeUpdatedItem(value, report, fmt.Sprintf("%s[%d]{id=342}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationFailureEventReport(v *s20.FailureEventReport, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.FailureEventReportChoiceTooEarlyInterRATHOReportFromEUTRAN && v.TooEarlyInterRATHOReportFromEUTRAN != nil {
		BridgeWalkValidationTooEarlyInterRATHOReportReportFromEUTRAN(v.TooEarlyInterRATHOReportFromEUTRAN, report, path+".tooEarlyInterRATHOReportFromEUTRAN", false)
	}
}
func BridgeWalkValidationHandoverNotify(v *s35.HandoverNotify, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s35.HandoverNotifyIEs().MMEUES1APID().Info(), s35.HandoverNotifyIEs().ENBUES1APID().Info(), s35.HandoverNotifyIEs().EUTRANCGI().Info(), s35.HandoverNotifyIEs().TAI().Info(), s35.HandoverNotifyIEs().TunnelInformationForBBF().Info(), s35.HandoverNotifyIEs().LHNID().Info(), s35.HandoverNotifyIEs().PSCellInformation().Info(), s35.HandoverNotifyIEs().NotifySourceeNB().Info(), s35.HandoverNotifyIEs().LTENTNTAIInformation().Info()}
			s25.BridgeMergeNestedValidation(report, s35.BridgeHandoverNotifyIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					s49.BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(176):
				if value, ok := fields[i].Value.AsTunnelInformationForBBF(); ok {
					BridgeWalkValidationTunnelInformation(value, report, fmt.Sprintf("%s[%d]{id=176}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(288):
				if value, ok := fields[i].Value.AsPSCellInformation(); ok {
					s49.BridgeWalkValidationPSCellInformation(value, report, fmt.Sprintf("%s[%d]{id=288}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverRequest(v *s49.HandoverRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s48.HandoverRequestIEs().MMEUES1APID().Info(), s48.HandoverRequestIEs().HandoverType().Info(), s48.HandoverRequestIEs().Cause().Info(), s48.HandoverRequestIEs().UEaggregateMaximumBitrate().Info(), s48.HandoverRequestIEs().ERABToBeSetupListHOReq().Info(), s48.HandoverRequestIEs().SourceToTargetTransparentContainer().Info(), s48.HandoverRequestIEs().UESecurityCapabilities().Info(), s48.HandoverRequestIEs().HandoverRestrictionList().Info(), s48.HandoverRequestIEs().TraceActivation().Info(), s48.HandoverRequestIEs().RequestType().Info(), s48.HandoverRequestIEs().SRVCCOperationPossible().Info(), s48.HandoverRequestIEs().SecurityContext().Info(), s48.HandoverRequestIEs().NASSecurityParameterstoEUTRAN().Info(), s48.HandoverRequestIEs().CSGId().Info(), s48.HandoverRequestIEs().CSGMembershipStatus().Info(), s48.HandoverRequestIEs().GUMMEIID().Info(), s48.HandoverRequestIEs().MMEUES1APID2().Info(), s48.HandoverRequestIEs().ManagementBasedMDTAllowed().Info(), s48.HandoverRequestIEs().ManagementBasedMDTPLMNList().Info(), s48.HandoverRequestIEs().MaskedIMEISV().Info(), s48.HandoverRequestIEs().ExpectedUEBehaviour().Info(), s48.HandoverRequestIEs().ProSeAuthorized().Info(), s48.HandoverRequestIEs().UEUserPlaneCIoTSupportIndicator().Info(), s48.HandoverRequestIEs().V2XServicesAuthorized().Info(), s48.HandoverRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s48.HandoverRequestIEs().EnhancedCoverageRestricted().Info(), s48.HandoverRequestIEs().NRUESecurityCapabilities().Info(), s48.HandoverRequestIEs().CEModeBRestricted().Info(), s48.HandoverRequestIEs().AerialUEsubscriptionInformation().Info(), s48.HandoverRequestIEs().PendingDataIndication().Info(), s48.HandoverRequestIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s48.HandoverRequestIEs().AdditionalRRMPriorityIndex().Info(), s48.HandoverRequestIEs().IABAuthorized().Info(), s48.HandoverRequestIEs().NRV2XServicesAuthorized().Info(), s48.HandoverRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s48.HandoverRequestIEs().PC5QoSParameters().Info(), s48.HandoverRequestIEs().UERadioCapabilityID().Info(), s48.HandoverRequestIEs().TimeRefDistribution().Info()}
			s25.BridgeMergeNestedValidation(report, s49.BridgeHandoverRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s49.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(53):
				if value, ok := fields[i].Value.AsERABToBeSetupListHOReq(); ok {
					BridgeWalkValidationERABToBeSetupListHOReq(value, report, fmt.Sprintf("%s[%d]{id=53}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(107):
				if value, ok := fields[i].Value.AsUESecurityCapabilities(); ok {
					BridgeWalkValidationUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=107}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(41):
				if value, ok := fields[i].Value.AsHandoverRestrictionList(); ok {
					s49.BridgeWalkValidationHandoverRestrictionList(value, report, fmt.Sprintf("%s[%d]{id=41}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(25):
				if value, ok := fields[i].Value.AsTraceActivation(); ok {
					BridgeWalkValidationTraceActivation(value, report, fmt.Sprintf("%s[%d]{id=25}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(98):
				if value, ok := fields[i].Value.AsRequestType(); ok {
					s49.BridgeWalkValidationRequestType(value, report, fmt.Sprintf("%s[%d]{id=98}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(40):
				if value, ok := fields[i].Value.AsSecurityContext(); ok {
					s49.BridgeWalkValidationSecurityContext(value, report, fmt.Sprintf("%s[%d]{id=40}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(75):
				if value, ok := fields[i].Value.AsGUMMEIID(); ok {
					s49.BridgeWalkValidationGUMMEI(value, report, fmt.Sprintf("%s[%d]{id=75}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(177):
				if value, ok := fields[i].Value.AsManagementBasedMDTPLMNList(); ok {
					s49.BridgeWalkValidationMDTPLMNList(value, report, fmt.Sprintf("%s[%d]{id=177}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(196):
				if value, ok := fields[i].Value.AsExpectedUEBehaviour(); ok {
					s49.BridgeWalkValidationExpectedUEBehaviour(value, report, fmt.Sprintf("%s[%d]{id=196}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(195):
				if value, ok := fields[i].Value.AsProSeAuthorized(); ok {
					s49.BridgeWalkValidationProSeAuthorized(value, report, fmt.Sprintf("%s[%d]{id=195}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(240):
				if value, ok := fields[i].Value.AsV2XServicesAuthorized(); ok {
					BridgeWalkValidationV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=240}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(248):
				if value, ok := fields[i].Value.AsUESidelinkAggregateMaximumBitrate(); ok {
					BridgeWalkValidationUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=248}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(269):
				if value, ok := fields[i].Value.AsNRUESecurityCapabilities(); ok {
					s49.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(306):
				if value, ok := fields[i].Value.AsNRV2XServicesAuthorized(); ok {
					s49.BridgeWalkValidationNRV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=306}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(307):
				if value, ok := fields[i].Value.AsNRUESidelinkAggregateMaximumBitrate(); ok {
					s49.BridgeWalkValidationNRUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=307}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(308):
				if value, ok := fields[i].Value.AsPC5QoSParameters(); ok {
					s49.BridgeWalkValidationPC5QoSParameters(value, report, fmt.Sprintf("%s[%d]{id=308}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverRequired(v *s34.HandoverRequired, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s34.HandoverRequiredIEs().MMEUES1APID().Info(), s34.HandoverRequiredIEs().ENBUES1APID().Info(), s34.HandoverRequiredIEs().HandoverType().Info(), s34.HandoverRequiredIEs().Cause().Info(), s34.HandoverRequiredIEs().TargetID().Info(), s34.HandoverRequiredIEs().DirectForwardingPathAvailability().Info(), s34.HandoverRequiredIEs().SRVCCHOIndication().Info(), s34.HandoverRequiredIEs().SourceToTargetTransparentContainer().Info(), s34.HandoverRequiredIEs().SourceToTargetTransparentContainerSecondary().Info(), s34.HandoverRequiredIEs().MSClassmark2().Info(), s34.HandoverRequiredIEs().MSClassmark3().Info(), s34.HandoverRequiredIEs().CSGId().Info(), s34.HandoverRequiredIEs().CellAccessMode().Info(), s34.HandoverRequiredIEs().PSServiceNotAvailable().Info()}
			s25.BridgeMergeNestedValidation(report, s34.BridgeHandoverRequiredIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s49.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(4):
				if value, ok := fields[i].Value.AsTargetID(); ok {
					BridgeWalkValidationTargetID(value, report, fmt.Sprintf("%s[%d]{id=4}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationImmediateMDT(v *s47.ImmediateMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.M1thresholdeventA2 != nil {
		s49.BridgeWalkValidationM1ThresholdEventA2(v.M1thresholdeventA2, report, path+".m1thresholdeventA2", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.M1periodicReporting != nil {
		s49.BridgeWalkValidationM1PeriodicReporting(v.M1periodicReporting, report, path+".m1periodicReporting", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s47.ImmediateMDTExtIEs().M3Configuration().Info()), s00.FieldInfo(s47.ImmediateMDTExtIEs().M4Configuration().Info()), s00.FieldInfo(s47.ImmediateMDTExtIEs().M5Configuration().Info()), s00.FieldInfo(s47.ImmediateMDTExtIEs().MDTLocationInfo().Info()), s00.FieldInfo(s47.ImmediateMDTExtIEs().M6Configuration().Info()), s00.FieldInfo(s47.ImmediateMDTExtIEs().M7Configuration().Info()), s00.FieldInfo(s47.ImmediateMDTExtIEs().BluetoothMeasurementConfiguration().Info()), s00.FieldInfo(s47.ImmediateMDTExtIEs().WLANMeasurementConfiguration().Info()), s00.FieldInfo(s47.ImmediateMDTExtIEs().SensorMeasurementConfiguration().Info())}
				s25.BridgeMergeNestedValidation(report, s47.BridgeImmediateMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(171):
					if value, ok := fields[i].ExtensionValue.AsM3Configuration(); ok {
						s49.BridgeWalkValidationM3Configuration(value, report, fmt.Sprintf("%s[%d]{id=171}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(172):
					if value, ok := fields[i].ExtensionValue.AsM4Configuration(); ok {
						s49.BridgeWalkValidationM4Configuration(value, report, fmt.Sprintf("%s[%d]{id=172}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(173):
					if value, ok := fields[i].ExtensionValue.AsM5Configuration(); ok {
						s49.BridgeWalkValidationM5Configuration(value, report, fmt.Sprintf("%s[%d]{id=173}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(220):
					if value, ok := fields[i].ExtensionValue.AsM6Configuration(); ok {
						s49.BridgeWalkValidationM6Configuration(value, report, fmt.Sprintf("%s[%d]{id=220}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(221):
					if value, ok := fields[i].ExtensionValue.AsM7Configuration(); ok {
						s49.BridgeWalkValidationM7Configuration(value, report, fmt.Sprintf("%s[%d]{id=221}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(284):
					if value, ok := fields[i].ExtensionValue.AsBluetoothMeasurementConfiguration(); ok {
						s49.BridgeWalkValidationBluetoothMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=284}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(285):
					if value, ok := fields[i].ExtensionValue.AsWLANMeasurementConfiguration(); ok {
						BridgeWalkValidationWLANMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=285}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(345):
					if value, ok := fields[i].ExtensionValue.AsSensorMeasurementConfiguration(); ok {
						BridgeWalkValidationSensorMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=345}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInformationOnRecommendedCellsAndENBsForPaging(v *s33.InformationOnRecommendedCellsAndENBsForPaging, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s49.BridgeWalkValidationRecommendedCellsForPaging(&v.RecommendedCellsForPaging, report, path+".recommendedCellsForPaging", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationRecommendedENBsForPaging(&v.RecommendENBsForPaging, report, path+".recommendENBsForPaging", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s27.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInitialContextSetupRequest(v *s49.InitialContextSetupRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s48.InitialContextSetupRequestIEs().MMEUES1APID().Info(), s48.InitialContextSetupRequestIEs().ENBUES1APID().Info(), s48.InitialContextSetupRequestIEs().UEaggregateMaximumBitrate().Info(), s48.InitialContextSetupRequestIEs().ERABToBeSetupListCtxtSUReq().Info(), s48.InitialContextSetupRequestIEs().UESecurityCapabilities().Info(), s48.InitialContextSetupRequestIEs().SecurityKey().Info(), s48.InitialContextSetupRequestIEs().TraceActivation().Info(), s48.InitialContextSetupRequestIEs().HandoverRestrictionList().Info(), s48.InitialContextSetupRequestIEs().UERadioCapability().Info(), s48.InitialContextSetupRequestIEs().SubscriberProfileIDforRFP().Info(), s48.InitialContextSetupRequestIEs().CSFallbackIndicator().Info(), s48.InitialContextSetupRequestIEs().SRVCCOperationPossible().Info(), s48.InitialContextSetupRequestIEs().CSGMembershipStatus().Info(), s48.InitialContextSetupRequestIEs().RegisteredLAI().Info(), s48.InitialContextSetupRequestIEs().GUMMEIID().Info(), s48.InitialContextSetupRequestIEs().MMEUES1APID2().Info(), s48.InitialContextSetupRequestIEs().ManagementBasedMDTAllowed().Info(), s48.InitialContextSetupRequestIEs().ManagementBasedMDTPLMNList().Info(), s48.InitialContextSetupRequestIEs().AdditionalCSFallbackIndicator().Info(), s48.InitialContextSetupRequestIEs().MaskedIMEISV().Info(), s48.InitialContextSetupRequestIEs().ExpectedUEBehaviour().Info(), s48.InitialContextSetupRequestIEs().ProSeAuthorized().Info(), s48.InitialContextSetupRequestIEs().UEUserPlaneCIoTSupportIndicator().Info(), s48.InitialContextSetupRequestIEs().V2XServicesAuthorized().Info(), s48.InitialContextSetupRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s48.InitialContextSetupRequestIEs().EnhancedCoverageRestricted().Info(), s48.InitialContextSetupRequestIEs().NRUESecurityCapabilities().Info(), s48.InitialContextSetupRequestIEs().CEModeBRestricted().Info(), s48.InitialContextSetupRequestIEs().AerialUEsubscriptionInformation().Info(), s48.InitialContextSetupRequestIEs().PendingDataIndication().Info(), s48.InitialContextSetupRequestIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s48.InitialContextSetupRequestIEs().AdditionalRRMPriorityIndex().Info(), s48.InitialContextSetupRequestIEs().IABAuthorized().Info(), s48.InitialContextSetupRequestIEs().NRV2XServicesAuthorized().Info(), s48.InitialContextSetupRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s48.InitialContextSetupRequestIEs().PC5QoSParameters().Info(), s48.InitialContextSetupRequestIEs().UERadioCapabilityID().Info(), s48.InitialContextSetupRequestIEs().CoarseUELocation().Info(), s48.InitialContextSetupRequestIEs().TimeRefDistribution().Info()}
			s25.BridgeMergeNestedValidation(report, s49.BridgeInitialContextSetupRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(24):
				if value, ok := fields[i].Value.AsERABToBeSetupListCtxtSUReq(); ok {
					BridgeWalkValidationERABToBeSetupListCtxtSUReq(value, report, fmt.Sprintf("%s[%d]{id=24}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(107):
				if value, ok := fields[i].Value.AsUESecurityCapabilities(); ok {
					BridgeWalkValidationUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=107}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(25):
				if value, ok := fields[i].Value.AsTraceActivation(); ok {
					BridgeWalkValidationTraceActivation(value, report, fmt.Sprintf("%s[%d]{id=25}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(41):
				if value, ok := fields[i].Value.AsHandoverRestrictionList(); ok {
					s49.BridgeWalkValidationHandoverRestrictionList(value, report, fmt.Sprintf("%s[%d]{id=41}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(159):
				if value, ok := fields[i].Value.AsRegisteredLAI(); ok {
					s49.BridgeWalkValidationLAI(value, report, fmt.Sprintf("%s[%d]{id=159}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(75):
				if value, ok := fields[i].Value.AsGUMMEIID(); ok {
					s49.BridgeWalkValidationGUMMEI(value, report, fmt.Sprintf("%s[%d]{id=75}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(177):
				if value, ok := fields[i].Value.AsManagementBasedMDTPLMNList(); ok {
					s49.BridgeWalkValidationMDTPLMNList(value, report, fmt.Sprintf("%s[%d]{id=177}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(196):
				if value, ok := fields[i].Value.AsExpectedUEBehaviour(); ok {
					s49.BridgeWalkValidationExpectedUEBehaviour(value, report, fmt.Sprintf("%s[%d]{id=196}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(195):
				if value, ok := fields[i].Value.AsProSeAuthorized(); ok {
					s49.BridgeWalkValidationProSeAuthorized(value, report, fmt.Sprintf("%s[%d]{id=195}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(240):
				if value, ok := fields[i].Value.AsV2XServicesAuthorized(); ok {
					BridgeWalkValidationV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=240}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(248):
				if value, ok := fields[i].Value.AsUESidelinkAggregateMaximumBitrate(); ok {
					BridgeWalkValidationUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=248}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(269):
				if value, ok := fields[i].Value.AsNRUESecurityCapabilities(); ok {
					s49.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(306):
				if value, ok := fields[i].Value.AsNRV2XServicesAuthorized(); ok {
					s49.BridgeWalkValidationNRV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=306}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(307):
				if value, ok := fields[i].Value.AsNRUESidelinkAggregateMaximumBitrate(); ok {
					s49.BridgeWalkValidationNRUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=307}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(308):
				if value, ok := fields[i].Value.AsPC5QoSParameters(); ok {
					s49.BridgeWalkValidationPC5QoSParameters(value, report, fmt.Sprintf("%s[%d]{id=308}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInitialUEMessage(v *s35.InitialUEMessage, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s35.InitialUEMessageIEs().ENBUES1APID().Info(), s35.InitialUEMessageIEs().NASPDU().Info(), s35.InitialUEMessageIEs().TAI().Info(), s35.InitialUEMessageIEs().EUTRANCGI().Info(), s35.InitialUEMessageIEs().RRCEstablishmentCause().Info(), s35.InitialUEMessageIEs().STMSI().Info(), s35.InitialUEMessageIEs().CSGId().Info(), s35.InitialUEMessageIEs().GUMMEIID().Info(), s35.InitialUEMessageIEs().CellAccessMode().Info(), s35.InitialUEMessageIEs().GWTransportLayerAddress().Info(), s35.InitialUEMessageIEs().RelayNodeIndicator().Info(), s35.InitialUEMessageIEs().GUMMEIType().Info(), s35.InitialUEMessageIEs().TunnelInformationForBBF().Info(), s35.InitialUEMessageIEs().SIPTOLGWTransportLayerAddress().Info(), s35.InitialUEMessageIEs().LHNID().Info(), s35.InitialUEMessageIEs().MMEGroupID().Info(), s35.InitialUEMessageIEs().UEUsageType().Info(), s35.InitialUEMessageIEs().CEModeBSupportIndicator().Info(), s35.InitialUEMessageIEs().DCNID().Info(), s35.InitialUEMessageIEs().CoverageLevel().Info(), s35.InitialUEMessageIEs().UEApplicationLayerMeasurementCapability().Info(), s35.InitialUEMessageIEs().EDTSession().Info(), s35.InitialUEMessageIEs().IABNodeIndication().Info(), s35.InitialUEMessageIEs().LTENTNTAIInformation().Info(), s35.InitialUEMessageIEs().CoarseUELocationRequested().Info()}
			s25.BridgeMergeNestedValidation(report, s35.BridgeInitialUEMessageIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					s49.BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(96):
				if value, ok := fields[i].Value.AsSTMSI(); ok {
					s49.BridgeWalkValidationSTMSI(value, report, fmt.Sprintf("%s[%d]{id=96}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(75):
				if value, ok := fields[i].Value.AsGUMMEIID(); ok {
					s49.BridgeWalkValidationGUMMEI(value, report, fmt.Sprintf("%s[%d]{id=75}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(176):
				if value, ok := fields[i].Value.AsTunnelInformationForBBF(); ok {
					BridgeWalkValidationTunnelInformation(value, report, fmt.Sprintf("%s[%d]{id=176}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInterSystemInformationTransferType(v *s33.InterSystemInformationTransferType, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.InterSystemInformationTransferTypeChoiceRIMTransfer && v.RIMTransfer != nil {
		BridgeWalkValidationRIMTransfer(v.RIMTransfer, report, path+".rIMTransfer", false)
	}
}
func BridgeWalkValidationKillRequest(v *s33.KillRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s33.KillRequestIEs().MessageIdentifier().Info(), s33.KillRequestIEs().SerialNumber().Info(), s33.KillRequestIEs().WarningAreaList().Info(), s33.KillRequestIEs().KillAllWarningMessages().Info()}
			s25.BridgeMergeNestedValidation(report, s33.BridgeKillRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(113):
				if value, ok := fields[i].Value.AsWarningAreaList(); ok {
					BridgeWalkValidationWarningAreaList(value, report, fmt.Sprintf("%s[%d]{id=113}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationKillResponse(v *s33.KillResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s32.KillResponseIEs().MessageIdentifier().Info(), s32.KillResponseIEs().SerialNumber().Info(), s32.KillResponseIEs().BroadcastCancelledAreaList().Info(), s32.KillResponseIEs().CriticalityDiagnostics().Info()}
			s25.BridgeMergeNestedValidation(report, s33.BridgeKillResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(141):
				if value, ok := fields[i].Value.AsBroadcastCancelledAreaList(); ok {
					BridgeWalkValidationBroadcastCancelledAreaList(value, report, fmt.Sprintf("%s[%d]{id=141}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLTENTNTAIInformation(v *s18.LTENTNTAIInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationTACListInLTENTN(&v.TACListInLTENTN, report, path+".tACList-In-LTE-NTN", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s27.BridgeLTENTNTAIInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLocationReport(v *s33.LocationReport, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s32.LocationReportIEs().MMEUES1APID().Info(), s32.LocationReportIEs().ENBUES1APID().Info(), s32.LocationReportIEs().EUTRANCGI().Info(), s32.LocationReportIEs().TAI().Info(), s32.LocationReportIEs().RequestType().Info(), s32.LocationReportIEs().PSCellInformation().Info(), s32.LocationReportIEs().LTENTNTAIInformation().Info()}
			s25.BridgeMergeNestedValidation(report, s33.BridgeLocationReportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					s49.BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(98):
				if value, ok := fields[i].Value.AsRequestType(); ok {
					s49.BridgeWalkValidationRequestType(value, report, fmt.Sprintf("%s[%d]{id=98}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(288):
				if value, ok := fields[i].Value.AsPSCellInformation(); ok {
					s49.BridgeWalkValidationPSCellInformation(value, report, fmt.Sprintf("%s[%d]{id=288}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLoggedMDT(v *s47.LoggedMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s47.LoggedMDTExtIEs().BluetoothMeasurementConfiguration().Info()), s00.FieldInfo(s47.LoggedMDTExtIEs().WLANMeasurementConfiguration().Info()), s00.FieldInfo(s47.LoggedMDTExtIEs().LoggedMDTTrigger().Info()), s00.FieldInfo(s47.LoggedMDTExtIEs().SensorMeasurementConfiguration().Info())}
				s25.BridgeMergeNestedValidation(report, s47.BridgeLoggedMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(284):
					if value, ok := fields[i].ExtensionValue.AsBluetoothMeasurementConfiguration(); ok {
						s49.BridgeWalkValidationBluetoothMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=284}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(285):
					if value, ok := fields[i].ExtensionValue.AsWLANMeasurementConfiguration(); ok {
						BridgeWalkValidationWLANMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=285}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(344):
					if value, ok := fields[i].ExtensionValue.AsLoggedMDTTrigger(); ok {
						s49.BridgeWalkValidationLoggedMDTTrigger(value, report, fmt.Sprintf("%s[%d]{id=344}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(345):
					if value, ok := fields[i].ExtensionValue.AsSensorMeasurementConfiguration(); ok {
						BridgeWalkValidationSensorMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=345}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMDTConfiguration(v *s47.MDTConfiguration, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationAreaScopeOfMDT(&v.AreaScopeOfMDT, report, path+".areaScopeOfMDT", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationMDTMode(&v.MDTMode, report, path+".mDTMode", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s42.MDTConfigurationExtIEs().SignallingBasedMDTPLMNList().Info())}
				s25.BridgeMergeNestedValidation(report, s42.BridgeMDTConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(178):
					if value, ok := fields[i].ExtensionValue.AsSignallingBasedMDTPLMNList(); ok {
						s49.BridgeWalkValidationMDTPLMNList(value, report, fmt.Sprintf("%s[%d]{id=178}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMDTMode(v *s47.MDTMode, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.MDTModeChoiceImmediateMDT && v.ImmediateMDT != nil {
		BridgeWalkValidationImmediateMDT(v.ImmediateMDT, report, path+".immediateMDT", false)
	}
	if v.Choice == s00.MDTModeChoiceLoggedMDT && v.LoggedMDT != nil {
		BridgeWalkValidationLoggedMDT(v.LoggedMDT, report, path+".loggedMDT", false)
	}
	if v.Choice == s00.MDTModeChoiceMDTModeExtension && v.MDTModeExtension != nil {
		s49.BridgeWalkValidationMDTModeExtension(v.MDTModeExtension, report, path+".mDTMode-Extension", false)
	}
}
func BridgeWalkValidationMMEConfigurationUpdate(v *s43.MMEConfigurationUpdate, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s43.MMEConfigurationUpdateIEs().MMEname().Info(), s43.MMEConfigurationUpdateIEs().ServedGUMMEIs().Info(), s43.MMEConfigurationUpdateIEs().RelativeMMECapacity().Info(), s43.MMEConfigurationUpdateIEs().ServedDCNs().Info()}
			s25.BridgeMergeNestedValidation(report, s43.BridgeMMEConfigurationUpdateIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(105):
				if value, ok := fields[i].Value.AsServedGUMMEIs(); ok {
					BridgeWalkValidationServedGUMMEIs(value, report, fmt.Sprintf("%s[%d]{id=105}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(247):
				if value, ok := fields[i].Value.AsServedDCNs(); ok {
					BridgeWalkValidationServedDCNs(value, report, fmt.Sprintf("%s[%d]{id=247}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMMEDirectInformationTransfer(v *s34.MMEDirectInformationTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s34.MMEDirectInformationTransferIEs().InterSystemInformationTransferTypeMDT().Info()}
			s25.BridgeMergeNestedValidation(report, s34.BridgeMMEDirectInformationTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(122):
				if value, ok := fields[i].Value.AsInterSystemInformationTransferTypeMDT(); ok {
					BridgeWalkValidationInterSystemInformationTransferType(value, report, fmt.Sprintf("%s[%d]{id=122}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMMEPagingTarget(v *s32.MMEPagingTarget, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.MMEPagingTargetChoiceGlobalENBID && v.GlobalENBID != nil {
		s49.BridgeWalkValidationGlobalENBID(v.GlobalENBID, report, path+".global-ENB-ID", false)
	}
	if v.Choice == s00.MMEPagingTargetChoiceTAI && v.TAI != nil {
		BridgeWalkValidationTAI(v.TAI, report, path+".tAI", false)
	}
}
func BridgeWalkValidationPWSRestartIndication(v *s44.PWSRestartIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s44.PWSRestartIndicationIEs().ECGIListForRestart().Info(), s44.PWSRestartIndicationIEs().GlobalENBID().Info(), s44.PWSRestartIndicationIEs().TAIListForRestart().Info(), s44.PWSRestartIndicationIEs().EmergencyAreaIDListForRestart().Info()}
			s25.BridgeMergeNestedValidation(report, s44.BridgePWSRestartIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(182):
				if value, ok := fields[i].Value.AsECGIListForRestart(); ok {
					s49.BridgeWalkValidationECGIListForRestart(value, report, fmt.Sprintf("%s[%d]{id=182}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(59):
				if value, ok := fields[i].Value.AsGlobalENBID(); ok {
					s49.BridgeWalkValidationGlobalENBID(value, report, fmt.Sprintf("%s[%d]{id=59}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(188):
				if value, ok := fields[i].Value.AsTAIListForRestart(); ok {
					BridgeWalkValidationTAIListForRestart(value, report, fmt.Sprintf("%s[%d]{id=188}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(190):
				if value, ok := fields[i].Value.AsEmergencyAreaIDListForRestart(); ok {
					s49.BridgeWalkValidationEmergencyAreaIDListForRestart(value, report, fmt.Sprintf("%s[%d]{id=190}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPaging(v *s49.Paging, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s49.PagingIEs().UEIdentityIndexValue().Info(), s49.PagingIEs().UEPagingID().Info(), s49.PagingIEs().PagingDRX().Info(), s49.PagingIEs().CNDomain().Info(), s49.PagingIEs().TAIList().Info(), s49.PagingIEs().CSGIdList().Info(), s49.PagingIEs().PagingPriority().Info(), s49.PagingIEs().UERadioCapabilityForPaging().Info(), s49.PagingIEs().AssistanceDataForPaging().Info(), s49.PagingIEs().PagingEDRXInformation().Info(), s49.PagingIEs().ExtendedUEIdentityIndexValue().Info(), s49.PagingIEs().NBIoTPagingEDRXInformation().Info(), s49.PagingIEs().NBIoTUEIdentityIndexValue().Info(), s49.PagingIEs().EnhancedCoverageRestricted().Info(), s49.PagingIEs().CEModeBRestricted().Info(), s49.PagingIEs().DataSize().Info(), s49.PagingIEs().WUSAssistanceInformation().Info(), s49.PagingIEs().NBIoTPagingDRX().Info(), s49.PagingIEs().PagingCause().Info()}
			s25.BridgeMergeNestedValidation(report, s49.BridgePagingIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(43):
				if value, ok := fields[i].Value.AsUEPagingID(); ok {
					BridgeWalkValidationUEPagingID(value, report, fmt.Sprintf("%s[%d]{id=43}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(46):
				if value, ok := fields[i].Value.AsTAIList(); ok {
					BridgeWalkValidationTAIList(value, report, fmt.Sprintf("%s[%d]{id=46}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(128):
				if value, ok := fields[i].Value.AsCSGIdList(); ok {
					s49.BridgeWalkValidationCSGIdList(value, report, fmt.Sprintf("%s[%d]{id=128}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(211):
				if value, ok := fields[i].Value.AsAssistanceDataForPaging(); ok {
					s49.BridgeWalkValidationAssistanceDataForPaging(value, report, fmt.Sprintf("%s[%d]{id=211}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(227):
				if value, ok := fields[i].Value.AsPagingEDRXInformation(); ok {
					s49.BridgeWalkValidationPagingEDRXInformation(value, report, fmt.Sprintf("%s[%d]{id=227}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(239):
				if value, ok := fields[i].Value.AsNBIoTPagingEDRXInformation(); ok {
					s49.BridgeWalkValidationNBIoTPagingEDRXInformation(value, report, fmt.Sprintf("%s[%d]{id=239}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(323):
				if value, ok := fields[i].Value.AsWUSAssistanceInformation(); ok {
					BridgeWalkValidationWUSAssistanceInformation(value, report, fmt.Sprintf("%s[%d]{id=323}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPathSwitchRequest(v *s41.PathSwitchRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s41.PathSwitchRequestIEs().ENBUES1APID().Info(), s41.PathSwitchRequestIEs().ERABToBeSwitchedDLList().Info(), s41.PathSwitchRequestIEs().SourceMMEUES1APID().Info(), s41.PathSwitchRequestIEs().EUTRANCGI().Info(), s41.PathSwitchRequestIEs().TAI().Info(), s41.PathSwitchRequestIEs().UESecurityCapabilities().Info(), s41.PathSwitchRequestIEs().CSGId().Info(), s41.PathSwitchRequestIEs().CellAccessMode().Info(), s41.PathSwitchRequestIEs().SourceMMEGUMMEI().Info(), s41.PathSwitchRequestIEs().CSGMembershipStatus().Info(), s41.PathSwitchRequestIEs().TunnelInformationForBBF().Info(), s41.PathSwitchRequestIEs().LHNID().Info(), s41.PathSwitchRequestIEs().RRCResumeCause().Info(), s41.PathSwitchRequestIEs().NRUESecurityCapabilities().Info(), s41.PathSwitchRequestIEs().PSCellInformation().Info(), s41.PathSwitchRequestIEs().LTENTNTAIInformation().Info()}
			s25.BridgeMergeNestedValidation(report, s41.BridgePathSwitchRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(22):
				if value, ok := fields[i].Value.AsERABToBeSwitchedDLList(); ok {
					BridgeWalkValidationERABToBeSwitchedDLList(value, report, fmt.Sprintf("%s[%d]{id=22}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					s49.BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(107):
				if value, ok := fields[i].Value.AsUESecurityCapabilities(); ok {
					BridgeWalkValidationUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=107}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(157):
				if value, ok := fields[i].Value.AsSourceMMEGUMMEI(); ok {
					s49.BridgeWalkValidationGUMMEI(value, report, fmt.Sprintf("%s[%d]{id=157}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(176):
				if value, ok := fields[i].Value.AsTunnelInformationForBBF(); ok {
					BridgeWalkValidationTunnelInformation(value, report, fmt.Sprintf("%s[%d]{id=176}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(269):
				if value, ok := fields[i].Value.AsNRUESecurityCapabilities(); ok {
					s49.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(288):
				if value, ok := fields[i].Value.AsPSCellInformation(); ok {
					s49.BridgeWalkValidationPSCellInformation(value, report, fmt.Sprintf("%s[%d]{id=288}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPathSwitchRequestAcknowledge(v *s47.PathSwitchRequestAcknowledge, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s47.PathSwitchRequestAcknowledgeIEs().MMEUES1APID().Info(), s47.PathSwitchRequestAcknowledgeIEs().ENBUES1APID().Info(), s47.PathSwitchRequestAcknowledgeIEs().UEaggregateMaximumBitrate().Info(), s47.PathSwitchRequestAcknowledgeIEs().ERABToBeSwitchedULList().Info(), s47.PathSwitchRequestAcknowledgeIEs().ERABToBeReleasedList().Info(), s47.PathSwitchRequestAcknowledgeIEs().SecurityContext().Info(), s47.PathSwitchRequestAcknowledgeIEs().CriticalityDiagnostics().Info(), s47.PathSwitchRequestAcknowledgeIEs().MMEUES1APID2().Info(), s47.PathSwitchRequestAcknowledgeIEs().CSGMembershipStatus().Info(), s47.PathSwitchRequestAcknowledgeIEs().ProSeAuthorized().Info(), s47.PathSwitchRequestAcknowledgeIEs().UEUserPlaneCIoTSupportIndicator().Info(), s47.PathSwitchRequestAcknowledgeIEs().V2XServicesAuthorized().Info(), s47.PathSwitchRequestAcknowledgeIEs().UESidelinkAggregateMaximumBitrate().Info(), s47.PathSwitchRequestAcknowledgeIEs().EnhancedCoverageRestricted().Info(), s47.PathSwitchRequestAcknowledgeIEs().NRUESecurityCapabilities().Info(), s47.PathSwitchRequestAcknowledgeIEs().CEModeBRestricted().Info(), s47.PathSwitchRequestAcknowledgeIEs().AerialUEsubscriptionInformation().Info(), s47.PathSwitchRequestAcknowledgeIEs().PendingDataIndication().Info(), s47.PathSwitchRequestAcknowledgeIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s47.PathSwitchRequestAcknowledgeIEs().HandoverRestrictionList().Info(), s47.PathSwitchRequestAcknowledgeIEs().AdditionalRRMPriorityIndex().Info(), s47.PathSwitchRequestAcknowledgeIEs().NRV2XServicesAuthorized().Info(), s47.PathSwitchRequestAcknowledgeIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s47.PathSwitchRequestAcknowledgeIEs().PC5QoSParameters().Info(), s47.PathSwitchRequestAcknowledgeIEs().UERadioCapabilityID().Info(), s47.PathSwitchRequestAcknowledgeIEs().UESecurityCapabilities().Info(), s47.PathSwitchRequestAcknowledgeIEs().ERABToBeUpdatedList().Info(), s47.PathSwitchRequestAcknowledgeIEs().TimeRefDistribution().Info()}
			s25.BridgeMergeNestedValidation(report, s47.BridgePathSwitchRequestAcknowledgeIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(95):
				if value, ok := fields[i].Value.AsERABToBeSwitchedULList(); ok {
					s49.BridgeWalkValidationERABToBeSwitchedULList(value, report, fmt.Sprintf("%s[%d]{id=95}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(33):
				if value, ok := fields[i].Value.AsERABToBeReleasedList(); ok {
					s49.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=33}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(40):
				if value, ok := fields[i].Value.AsSecurityContext(); ok {
					s49.BridgeWalkValidationSecurityContext(value, report, fmt.Sprintf("%s[%d]{id=40}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(195):
				if value, ok := fields[i].Value.AsProSeAuthorized(); ok {
					s49.BridgeWalkValidationProSeAuthorized(value, report, fmt.Sprintf("%s[%d]{id=195}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(240):
				if value, ok := fields[i].Value.AsV2XServicesAuthorized(); ok {
					BridgeWalkValidationV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=240}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(248):
				if value, ok := fields[i].Value.AsUESidelinkAggregateMaximumBitrate(); ok {
					BridgeWalkValidationUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=248}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(269):
				if value, ok := fields[i].Value.AsNRUESecurityCapabilities(); ok {
					s49.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(41):
				if value, ok := fields[i].Value.AsHandoverRestrictionList(); ok {
					s49.BridgeWalkValidationHandoverRestrictionList(value, report, fmt.Sprintf("%s[%d]{id=41}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(306):
				if value, ok := fields[i].Value.AsNRV2XServicesAuthorized(); ok {
					s49.BridgeWalkValidationNRV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=306}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(307):
				if value, ok := fields[i].Value.AsNRUESidelinkAggregateMaximumBitrate(); ok {
					s49.BridgeWalkValidationNRUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=307}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(308):
				if value, ok := fields[i].Value.AsPC5QoSParameters(); ok {
					s49.BridgeWalkValidationPC5QoSParameters(value, report, fmt.Sprintf("%s[%d]{id=308}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(107):
				if value, ok := fields[i].Value.AsUESecurityCapabilities(); ok {
					BridgeWalkValidationUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=107}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(341):
				if value, ok := fields[i].Value.AsERABToBeUpdatedList(); ok {
					BridgeWalkValidationERABToBeUpdatedList(value, report, fmt.Sprintf("%s[%d]{id=341}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRIMRoutingAddress(v *s33.RIMRoutingAddress, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.RIMRoutingAddressChoiceGERANCellID && v.GERANCellID != nil {
		s49.BridgeWalkValidationGERANCellID(v.GERANCellID, report, path+".gERAN-Cell-ID", false)
	}
	if v.Choice == s00.RIMRoutingAddressChoiceTargetRNCID && v.TargetRNCID != nil {
		BridgeWalkValidationTargetRNCID(v.TargetRNCID, report, path+".targetRNC-ID", false)
	}
}
func BridgeWalkValidationRIMTransfer(v *s33.RIMTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.RIMRoutingAddress != nil {
		BridgeWalkValidationRIMRoutingAddress(v.RIMRoutingAddress, report, path+".rIMRoutingAddress", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s27.BridgeRIMTransferExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRecommendedENBItem(v *s32.RecommendedENBItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationMMEPagingTarget(&v.MMEPagingTarget, report, path+".mMEPagingTarget", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s27.BridgeRecommendedENBItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRecommendedENBList(v *s32.RecommendedENBList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s32.RecommendedENBItemIEs().RecommendedENBItem().Info()}
		s25.BridgeMergeNestedValidation(report, s33.BridgeRecommendedENBItemIEValueValidateS1APIEContainer(s32.RecommendedENBItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s32.RecommendedENBItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(215):
				if value, ok := fields[i].Value.AsRecommendedENBItem(); ok {
					BridgeWalkValidationRecommendedENBItem(value, report, fmt.Sprintf("%s[%d]{id=215}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationRecommendedENBsForPaging(v *s33.RecommendedENBsForPaging, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationRecommendedENBList(&v.RecommendedENBList, report, path+".recommendedENBList", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s27.BridgeRecommendedENBsForPagingExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationReset(v *s36.Reset, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s36.ResetIEs().Cause().Info(), s36.ResetIEs().ResetType().Info()}
			s25.BridgeMergeNestedValidation(report, s36.BridgeResetIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s49.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(92):
				if value, ok := fields[i].Value.AsResetType(); ok {
					BridgeWalkValidationResetType(value, report, fmt.Sprintf("%s[%d]{id=92}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResetAcknowledge(v *s44.ResetAcknowledge, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s44.ResetAcknowledgeIEs().UEAssociatedLogicalS1ConnectionListResAck().Info(), s44.ResetAcknowledgeIEs().CriticalityDiagnostics().Info()}
			s25.BridgeMergeNestedValidation(report, s44.BridgeResetAcknowledgeIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(93):
				if value, ok := fields[i].Value.AsUEAssociatedLogicalS1ConnectionListResAck(); ok {
					BridgeWalkValidationUEAssociatedLogicalS1ConnectionListResAck(value, report, fmt.Sprintf("%s[%d]{id=93}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResetType(v *s36.ResetType, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.ResetTypeChoicePartOfS1Interface && v.PartOfS1Interface != nil {
		BridgeWalkValidationUEAssociatedLogicalS1ConnectionListRes(&v.PartOfS1Interface, report, path+".partOfS1-Interface", false)
	}
}
func BridgeWalkValidationS1SetupRequest(v *s44.S1SetupRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s43.S1SetupRequestIEs().GlobalENBID().Info(), s43.S1SetupRequestIEs().ENBname().Info(), s43.S1SetupRequestIEs().SupportedTAs().Info(), s43.S1SetupRequestIEs().DefaultPagingDRX().Info(), s43.S1SetupRequestIEs().CSGIdList().Info(), s43.S1SetupRequestIEs().UERetentionInformation().Info(), s43.S1SetupRequestIEs().NBIoTDefaultPagingDRX().Info(), s43.S1SetupRequestIEs().ConnectedengNBList().Info()}
			s25.BridgeMergeNestedValidation(report, s44.BridgeS1SetupRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(59):
				if value, ok := fields[i].Value.AsGlobalENBID(); ok {
					s49.BridgeWalkValidationGlobalENBID(value, report, fmt.Sprintf("%s[%d]{id=59}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(64):
				if value, ok := fields[i].Value.AsSupportedTAs(); ok {
					BridgeWalkValidationSupportedTAs(value, report, fmt.Sprintf("%s[%d]{id=64}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(128):
				if value, ok := fields[i].Value.AsCSGIdList(); ok {
					s49.BridgeWalkValidationCSGIdList(value, report, fmt.Sprintf("%s[%d]{id=128}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(291):
				if value, ok := fields[i].Value.AsConnectedengNBList(); ok {
					BridgeWalkValidationConnectedengNBList(value, report, fmt.Sprintf("%s[%d]{id=291}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationS1SetupResponse(v *s43.S1SetupResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s43.S1SetupResponseIEs().MMEname().Info(), s43.S1SetupResponseIEs().ServedGUMMEIs().Info(), s43.S1SetupResponseIEs().RelativeMMECapacity().Info(), s43.S1SetupResponseIEs().MMERelaySupportIndicator().Info(), s43.S1SetupResponseIEs().CriticalityDiagnostics().Info(), s43.S1SetupResponseIEs().UERetentionInformation().Info(), s43.S1SetupResponseIEs().ServedDCNs().Info(), s43.S1SetupResponseIEs().IABSupported().Info()}
			s25.BridgeMergeNestedValidation(report, s43.BridgeS1SetupResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(105):
				if value, ok := fields[i].Value.AsServedGUMMEIs(); ok {
					BridgeWalkValidationServedGUMMEIs(value, report, fmt.Sprintf("%s[%d]{id=105}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(247):
				if value, ok := fields[i].Value.AsServedDCNs(); ok {
					BridgeWalkValidationServedDCNs(value, report, fmt.Sprintf("%s[%d]{id=247}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSONtransferRequestContainer(v *s24.SONtransferRequestContainer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.SONtransferRequestContainerChoiceMultiCellLoadReporting && v.MultiCellLoadReporting != nil {
		s49.BridgeWalkValidationMultiCellLoadReportingRequest(v.MultiCellLoadReporting, report, path+".multiCellLoadReporting", false)
	}
	if v.Choice == s00.SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting && v.EventTriggeredCellLoadReporting != nil {
		s49.BridgeWalkValidationEventTriggeredCellLoadReportingRequest(v.EventTriggeredCellLoadReporting, report, path+".eventTriggeredCellLoadReporting", false)
	}
	if v.Choice == s00.SONtransferRequestContainerChoiceHOReporting && v.HOReporting != nil {
		s49.BridgeWalkValidationHOReport(v.HOReporting, report, path+".hOReporting", false)
	}
	if v.Choice == s00.SONtransferRequestContainerChoiceEutranCellActivation && v.EutranCellActivation != nil {
		s49.BridgeWalkValidationCellActivationRequest(v.EutranCellActivation, report, path+".eutranCellActivation", false)
	}
	if v.Choice == s00.SONtransferRequestContainerChoiceEnergySavingsIndication && v.EnergySavingsIndication != nil {
		s49.BridgeWalkValidationCellStateIndication(v.EnergySavingsIndication, report, path+".energySavingsIndication", false)
	}
	if v.Choice == s00.SONtransferRequestContainerChoiceFailureEventReporting && v.FailureEventReporting != nil {
		BridgeWalkValidationFailureEventReport(v.FailureEventReporting, report, path+".failureEventReporting", false)
	}
}
func BridgeWalkValidationSecondaryRATDataUsageReport(v *s46.SecondaryRATDataUsageReport, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s45.SecondaryRATDataUsageReportIEs().MMEUES1APID().Info(), s45.SecondaryRATDataUsageReportIEs().ENBUES1APID().Info(), s45.SecondaryRATDataUsageReportIEs().SecondaryRATDataUsageReportList().Info(), s45.SecondaryRATDataUsageReportIEs().HandoverFlag().Info(), s45.SecondaryRATDataUsageReportIEs().UserLocationInformation().Info(), s45.SecondaryRATDataUsageReportIEs().TimeSinceSecondaryNodeRelease().Info()}
			s25.BridgeMergeNestedValidation(report, s46.BridgeSecondaryRATDataUsageReportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s49.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSecurityResult(v *s30.SecurityResult, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s30.BridgeSecurityResultExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSensorMeasConfigNameItem(v *s30.SensorMeasConfigNameItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationSensorNameConfig(&v.SensorNameConfig, report, path+".sensorNameConfig", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s30.BridgeSensorMeasConfigNameItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSensorMeasConfigNameList(v *s30.SensorMeasConfigNameList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationSensorMeasConfigNameItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationSensorMeasurementConfiguration(v *s30.SensorMeasurementConfiguration, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.SensorMeasConfigNameList != nil {
		BridgeWalkValidationSensorMeasConfigNameList(&v.SensorMeasConfigNameList, report, path+".sensorMeasConfigNameList", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s30.BridgeSensorMeasurementConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSensorNameConfig(v *s30.SensorNameConfig, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationServedDCNs(v *s30.ServedDCNs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationServedDCNsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationServedDCNsItem(v *s30.ServedDCNsItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s30.BridgeServedDCNsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationServedGUMMEIs(v *s30.ServedGUMMEIs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationServedGUMMEIsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationServedGUMMEIsItem(v *s30.ServedGUMMEIsItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationServedPLMNs(&v.ServedPLMNs, report, path+".servedPLMNs", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationServedGroupIDs(&v.ServedGroupIDs, report, path+".servedGroupIDs", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationServedMMECs(&v.ServedMMECs, report, path+".servedMMECs", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s11.ServedGUMMEIsItemExtIEs().GUMMEIType().Info())}
				s25.BridgeMergeNestedValidation(report, s30.BridgeServedGUMMEIsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationServedGroupIDs(v *s00.ServedGroupIDs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationServedMMECs(v *s00.ServedMMECs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationServedPLMNs(v *s00.ServedPLMNs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationSourceNgRanNodeID(v *s30.SourceNgRanNodeID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s49.BridgeWalkValidationGlobalRANNODEID(&v.GlobalRANNODEID, report, path+".global-RAN-NODE-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s49.BridgeWalkValidationFiveGSTAI(&v.SelectedTAI, report, path+".selected-TAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s30.BridgeSourceNgRanNodeIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSourceNodeID(v *s30.SourceNodeID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.SourceNodeIDChoiceSourceNgRanNodeID && v.SourceNgRanNodeID != nil {
		BridgeWalkValidationSourceNgRanNodeID(v.SourceNgRanNodeID, report, path+".sourceNgRanNode-ID", false)
	}
	if v.Choice == s00.SourceNodeIDChoiceSourceNodeIDExtension && v.SourceNodeIDExtension != nil {
		BridgeWalkValidationSourceNodeIDExtension(v.SourceNodeIDExtension, report, path+".sourceNodeID-Extension", false)
	}
}
func BridgeWalkValidationSourceNodeIDExtension(v *s20.SourceNodeIDExtension, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSourceeNBID(v *s32.SourceeNBID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s49.BridgeWalkValidationGlobalENBID(&v.GlobalENBID, report, path+".global-ENB-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationTAI(&v.SelectedTAI, report, path+".selected-TAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s30.BridgeSourceeNBIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSourceeNBToTargeteNBTransparentContainer(v *s42.SourceeNBToTargeteNBTransparentContainer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.ERABInformationList != nil {
		s49.BridgeWalkValidationERABInformationList(&v.ERABInformationList, report, path+".e-RABInformationList", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s49.BridgeWalkValidationEUTRANCGI(&v.TargetCellID, report, path+".targetCell-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationUEHistoryInformation(&v.UEHistoryInformation, report, path+".uE-HistoryInformation", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s34.SourceeNBToTargeteNBTransparentContainerExtIEs().MobilityInformation().Info()), s00.FieldInfo(s34.SourceeNBToTargeteNBTransparentContainerExtIEs().UEHistoryInformationFromTheUE().Info()), s00.FieldInfo(s34.SourceeNBToTargeteNBTransparentContainerExtIEs().IMSvoiceEPSfallbackfrom5G().Info()), s00.FieldInfo(s34.SourceeNBToTargeteNBTransparentContainerExtIEs().AdditionalRRMPriorityIndex().Info()), s00.FieldInfo(s34.SourceeNBToTargeteNBTransparentContainerExtIEs().ContextatSource().Info()), s00.FieldInfo(s34.SourceeNBToTargeteNBTransparentContainerExtIEs().IntersystemMeasurementConfiguration().Info()), s00.FieldInfo(s34.SourceeNBToTargeteNBTransparentContainerExtIEs().SourceNodeID().Info()), s00.FieldInfo(s34.SourceeNBToTargeteNBTransparentContainerExtIEs().EmergencyIndicator().Info()), s00.FieldInfo(s34.SourceeNBToTargeteNBTransparentContainerExtIEs().UEContextReferenceatSourceeNB().Info()), s00.FieldInfo(s34.SourceeNBToTargeteNBTransparentContainerExtIEs().SourceSNID().Info()), s00.FieldInfo(s34.SourceeNBToTargeteNBTransparentContainerExtIEs().DirectForwardingPathAvailability().Info()), s00.FieldInfo(s34.SourceeNBToTargeteNBTransparentContainerExtIEs().TimeBasedHandoverInformation().Info())}
				s25.BridgeMergeNestedValidation(report, s34.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(300):
					if value, ok := fields[i].ExtensionValue.AsContextatSource(); ok {
						s49.BridgeWalkValidationContextatSource(value, report, fmt.Sprintf("%s[%d]{id=300}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(311):
					if value, ok := fields[i].ExtensionValue.AsIntersystemMeasurementConfiguration(); ok {
						s49.BridgeWalkValidationIntersystemMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=311}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(312):
					if value, ok := fields[i].ExtensionValue.AsSourceNodeID(); ok {
						BridgeWalkValidationSourceNodeID(value, report, fmt.Sprintf("%s[%d]{id=312}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(343):
					if value, ok := fields[i].ExtensionValue.AsSourceSNID(); ok {
						s49.BridgeWalkValidationGlobalRANNODEID(value, report, fmt.Sprintf("%s[%d]{id=343}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(350):
					if value, ok := fields[i].ExtensionValue.AsTimeBasedHandoverInformation(); ok {
						BridgeWalkValidationTimeBasedHandoverInformation(value, report, fmt.Sprintf("%s[%d]{id=350}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(v *s30.SubscriptionBasedUEDifferentiationInfo, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.ScheduledCommunicationTime != nil {
		s49.BridgeWalkValidationScheduledCommunicationTime(v.ScheduledCommunicationTime, report, path+".scheduledCommunicationTime", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s31.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSuccessfulOutcome(v *SuccessfulOutcome, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSupportedTAs(v *s31.SupportedTAs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationSupportedTAsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationSupportedTAsItem(v *s31.SupportedTAsItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s49.BridgeWalkValidationBPLMNs(&v.BroadcastPLMNs, report, path+".broadcastPLMNs", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s11.SupportedTAsItemExtIEs().RATType().Info())}
				s25.BridgeMergeNestedValidation(report, s31.BridgeSupportedTAsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSynchronisationInformation(v *s31.SynchronisationInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.ListeningSubframePattern != nil {
		s49.BridgeWalkValidationListeningSubframePattern(v.ListeningSubframePattern, report, path+".listeningSubframePattern", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.AggressoreCGIList != nil {
		s49.BridgeWalkValidationIEsECGIList(&v.AggressoreCGIList, report, path+".aggressoreCGI-List", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s31.BridgeSynchronisationInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTABasedMDT(v *s31.TABasedMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAListforMDT(&v.TAListforMDT, report, path+".tAListforMDT", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s31.BridgeTABasedMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTABasedQMC(v *s31.TABasedQMC, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAListforQMC(&v.TAListforQMC, report, path+".tAListforQMC", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s31.BridgeTABasedQMCExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTACListInLTENTN(v *s00.TACListInLTENTN, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationTAI(v *s31.TAI, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s33.BridgeTAIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAIBasedMDT(v *s32.TAIBasedMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAIListforMDT(&v.TAIListforMDT, report, path+".tAIListforMDT", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s31.BridgeTAIBasedMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAIBasedQMC(v *s32.TAIBasedQMC, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAIListforQMC(&v.TAIListforQMC, report, path+".tAIListforQMC", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s31.BridgeTAIBasedQMCExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAIBroadcast(v *s32.TAIBroadcast, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationTAIBroadcastItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAIBroadcastItem(v *s32.TAIBroadcastItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAI(&v.TAI, report, path+".tAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s49.BridgeWalkValidationCompletedCellinTAI(&v.CompletedCellinTAI, report, path+".completedCellinTAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s31.BridgeTAIBroadcastItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAICancelled(v *s32.TAICancelled, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationTAICancelledItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAICancelledItem(v *s32.TAICancelledItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAI(&v.TAI, report, path+".tAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s49.BridgeWalkValidationCancelledCellinTAI(&v.CancelledCellinTAI, report, path+".cancelledCellinTAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s31.BridgeTAICancelledItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAIItem(v *s33.TAIItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAI(&v.TAI, report, path+".tAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s33.BridgeTAIItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAIList(v *s33.TAIList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s33.TAIItemIEs().TAIItem().Info()}
		s25.BridgeMergeNestedValidation(report, s33.BridgeTAIItemIEValueValidateS1APIEContainer(s33.TAIItemIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s33.TAIItemIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(47):
				if value, ok := fields[i].Value.AsTAIItem(); ok {
					BridgeWalkValidationTAIItem(value, report, fmt.Sprintf("%s[%d]{id=47}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationTAIListForRestart(v *s32.TAIListForRestart, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationTAI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAIListforMDT(v *s32.TAIListforMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationTAI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAIListforQMC(v *s32.TAIListforQMC, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationTAI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAIListforWarning(v *s32.TAIListforWarning, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationTAI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAListforMDT(v *s00.TAListforMDT, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationTAListforQMC(v *s00.TAListforQMC, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationTargetID(v *s34.TargetID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.TargetIDChoiceTargeteNBID && v.TargeteNBID != nil {
		BridgeWalkValidationTargeteNBID(v.TargeteNBID, report, path+".targeteNB-ID", false)
	}
	if v.Choice == s00.TargetIDChoiceTargetRNCID && v.TargetRNCID != nil {
		BridgeWalkValidationTargetRNCID(v.TargetRNCID, report, path+".targetRNC-ID", false)
	}
	if v.Choice == s00.TargetIDChoiceCGI && v.CGI != nil {
		s49.BridgeWalkValidationCGI(v.CGI, report, path+".cGI", false)
	}
	if v.Choice == s00.TargetIDChoiceTargetgNgRanNodeID && v.TargetgNgRanNodeID != nil {
		BridgeWalkValidationTargetNgRanNodeID(v.TargetgNgRanNodeID, report, path+".targetgNgRanNode-ID", false)
	}
}
func BridgeWalkValidationTargetNgRanNodeID(v *s33.TargetNgRanNodeID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s49.BridgeWalkValidationGlobalRANNODEID(&v.GlobalRANNODEID, report, path+".global-RAN-NODE-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s49.BridgeWalkValidationFiveGSTAI(&v.SelectedTAI, report, path+".selected-TAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s33.BridgeTargetNgRanNodeIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTargetRNCID(v *s33.TargetRNCID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s49.BridgeWalkValidationLAI(&v.LAI, report, path+".lAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s34.BridgeTargetRNCIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTargeteNBID(v *s34.TargeteNBID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s49.BridgeWalkValidationGlobalENBID(&v.GlobalENBID, report, path+".global-ENB-ID", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationTAI(&v.SelectedTAI, report, path+".selected-TAI", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s34.BridgeTargeteNBIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTargeteNBToSourceeNBTransparentContainer(v *s39.TargeteNBToSourceeNBTransparentContainer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s39.TargeteNBToSourceeNBTransparentContainerExtIEs().DAPSResponseInfoList().Info()), s00.FieldInfo(s39.TargeteNBToSourceeNBTransparentContainerExtIEs().RACSIndication().Info()), s00.FieldInfo(s39.TargeteNBToSourceeNBTransparentContainerExtIEs().ERABSecurityResultList().Info()), s00.FieldInfo(s39.TargeteNBToSourceeNBTransparentContainerExtIEs().DirectForwardingPathAvailability().Info())}
				s25.BridgeMergeNestedValidation(report, s39.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(318):
					if value, ok := fields[i].ExtensionValue.AsDAPSResponseInfoList(); ok {
						s49.BridgeWalkValidationDAPSResponseInfoList(value, report, fmt.Sprintf("%s[%d]{id=318}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(335):
					if value, ok := fields[i].ExtensionValue.AsERABSecurityResultList(); ok {
						BridgeWalkValidationERABSecurityResultList(value, report, fmt.Sprintf("%s[%d]{id=335}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTimeBasedHandoverInformation(v *s34.TimeBasedHandoverInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s34.BridgeTimeBasedHandoverInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTimeSynchronisationInfo(v *s34.TimeSynchronisationInfo, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s12.TimeSynchronisationInfoExtIEs().MutingAvailabilityIndication().Info())}
				s25.BridgeMergeNestedValidation(report, s35.BridgeTimeSynchronisationInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTooEarlyInterRATHOReportReportFromEUTRAN(v *s20.TooEarlyInterRATHOReportReportFromEUTRAN, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTraceActivation(v *s47.TraceActivation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s47.TraceActivationExtIEs().MDTConfiguration().Info()), s00.FieldInfo(s47.TraceActivationExtIEs().UEAppLayerMeasConfig().Info()), s00.FieldInfo(s47.TraceActivationExtIEs().MDTConfigurationNR().Info()), s00.FieldInfo(s47.TraceActivationExtIEs().TraceCollectionEntityURI().Info())}
				s25.BridgeMergeNestedValidation(report, s49.BridgeTraceActivationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(162):
					if value, ok := fields[i].ExtensionValue.AsMDTConfiguration(); ok {
						BridgeWalkValidationMDTConfiguration(value, report, fmt.Sprintf("%s[%d]{id=162}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(262):
					if value, ok := fields[i].ExtensionValue.AsUEAppLayerMeasConfig(); ok {
						BridgeWalkValidationUEAppLayerMeasConfig(value, report, fmt.Sprintf("%s[%d]{id=262}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTraceFailureIndication(v *s35.TraceFailureIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s21.TraceFailureIndicationIEs().MMEUES1APID().Info(), s21.TraceFailureIndicationIEs().ENBUES1APID().Info(), s21.TraceFailureIndicationIEs().EUTRANTraceID().Info(), s21.TraceFailureIndicationIEs().Cause().Info()}
			s25.BridgeMergeNestedValidation(report, s35.BridgeTraceFailureIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s49.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTraceStart(v *s49.TraceStart, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s49.TraceStartIEs().MMEUES1APID().Info(), s49.TraceStartIEs().ENBUES1APID().Info(), s49.TraceStartIEs().TraceActivation().Info()}
			s25.BridgeMergeNestedValidation(report, s49.BridgeTraceStartIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(25):
				if value, ok := fields[i].Value.AsTraceActivation(); ok {
					BridgeWalkValidationTraceActivation(value, report, fmt.Sprintf("%s[%d]{id=25}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTransportInformation(v *s21.TransportInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTunnelInformation(v *s35.TunnelInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s35.BridgeTunnelInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEAggregateMaximumBitrate(v *s35.UEAggregateMaximumBitrate, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s12.UEAggregateMaximumBitratesExtIEs().ExtendedUEaggregateMaximumBitRateDL().Info()), s00.FieldInfo(s12.UEAggregateMaximumBitratesExtIEs().ExtendedUEaggregateMaximumBitRateUL().Info())}
				s25.BridgeMergeNestedValidation(report, s35.BridgeUEAggregateMaximumBitratesExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEAppLayerMeasConfig(v *s35.UEAppLayerMeasConfig, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationAreaScopeOfQMC(&v.AreaScopeOfQMC, report, path+".areaScopeOfQMC", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s12.UEAppLayerMeasConfigExtIEs().ServiceType().Info())}
				s25.BridgeMergeNestedValidation(report, s35.BridgeUEAppLayerMeasConfigExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEAssociatedLogicalS1ConnectionItem(v *s35.UEAssociatedLogicalS1ConnectionItem, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s36.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEAssociatedLogicalS1ConnectionListRes(v *s36.UEAssociatedLogicalS1ConnectionListRes, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s35.UEAssociatedLogicalS1ConnectionItemRes().UEAssociatedLogicalS1ConnectionItem().Info()}
		s25.BridgeMergeNestedValidation(report, s36.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueValidateS1APIEContainer(s35.UEAssociatedLogicalS1ConnectionItemResIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s35.UEAssociatedLogicalS1ConnectionItemResIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(91):
				if value, ok := fields[i].Value.AsUEAssociatedLogicalS1ConnectionItem(); ok {
					BridgeWalkValidationUEAssociatedLogicalS1ConnectionItem(value, report, fmt.Sprintf("%s[%d]{id=91}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationUEAssociatedLogicalS1ConnectionListResAck(v *s36.UEAssociatedLogicalS1ConnectionListResAck, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s35.UEAssociatedLogicalS1ConnectionItemResAck().UEAssociatedLogicalS1ConnectionItem().Info()}
		s25.BridgeMergeNestedValidation(report, s36.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueValidateS1APIEContainer(s35.UEAssociatedLogicalS1ConnectionItemResAckIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s35.UEAssociatedLogicalS1ConnectionItemResAckIEContainer{field}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(91):
				if value, ok := fields[i].Value.AsUEAssociatedLogicalS1ConnectionItem(); ok {
					BridgeWalkValidationUEAssociatedLogicalS1ConnectionItem(value, report, fmt.Sprintf("%s[%d]{id=91}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationUECapabilityInfoIndication(v *s36.UECapabilityInfoIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s12.UECapabilityInfoIndicationIEs().MMEUES1APID().Info(), s12.UECapabilityInfoIndicationIEs().ENBUES1APID().Info(), s12.UECapabilityInfoIndicationIEs().UERadioCapability().Info(), s12.UECapabilityInfoIndicationIEs().UERadioCapabilityForPaging().Info(), s12.UECapabilityInfoIndicationIEs().UEApplicationLayerMeasurementCapability().Info(), s12.UECapabilityInfoIndicationIEs().LTEMIndication().Info(), s12.UECapabilityInfoIndicationIEs().UERadioCapabilityNRFormat().Info(), s12.UECapabilityInfoIndicationIEs().UERadioCapabilityForPagingNRFormat().Info()}
			s25.BridgeMergeNestedValidation(report, s36.BridgeUECapabilityInfoIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextModificationConfirm(v *s36.UEContextModificationConfirm, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s23.UEContextModificationConfirmIEs().MMEUES1APID().Info(), s23.UEContextModificationConfirmIEs().ENBUES1APID().Info(), s23.UEContextModificationConfirmIEs().CSGMembershipStatus().Info(), s23.UEContextModificationConfirmIEs().CriticalityDiagnostics().Info()}
			s25.BridgeMergeNestedValidation(report, s36.BridgeUEContextModificationConfirmIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextModificationFailure(v *s36.UEContextModificationFailure, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s23.UEContextModificationFailureIEs().MMEUES1APID().Info(), s23.UEContextModificationFailureIEs().ENBUES1APID().Info(), s23.UEContextModificationFailureIEs().Cause().Info(), s23.UEContextModificationFailureIEs().CriticalityDiagnostics().Info()}
			s25.BridgeMergeNestedValidation(report, s36.BridgeUEContextModificationFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s49.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextModificationIndication(v *s36.UEContextModificationIndication, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s21.UEContextModificationIndicationIEs().MMEUES1APID().Info(), s21.UEContextModificationIndicationIEs().ENBUES1APID().Info(), s21.UEContextModificationIndicationIEs().CSGMembershipInfo().Info()}
			s25.BridgeMergeNestedValidation(report, s36.BridgeUEContextModificationIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(226):
				if value, ok := fields[i].Value.AsCSGMembershipInfo(); ok {
					s49.BridgeWalkValidationCSGMembershipInfo(value, report, fmt.Sprintf("%s[%d]{id=226}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextModificationRequest(v *s47.UEContextModificationRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s47.UEContextModificationRequestIEs().MMEUES1APID().Info(), s47.UEContextModificationRequestIEs().ENBUES1APID().Info(), s47.UEContextModificationRequestIEs().SecurityKey().Info(), s47.UEContextModificationRequestIEs().SubscriberProfileIDforRFP().Info(), s47.UEContextModificationRequestIEs().UEaggregateMaximumBitrate().Info(), s47.UEContextModificationRequestIEs().CSFallbackIndicator().Info(), s47.UEContextModificationRequestIEs().UESecurityCapabilities().Info(), s47.UEContextModificationRequestIEs().CSGMembershipStatus().Info(), s47.UEContextModificationRequestIEs().RegisteredLAI().Info(), s47.UEContextModificationRequestIEs().AdditionalCSFallbackIndicator().Info(), s47.UEContextModificationRequestIEs().ProSeAuthorized().Info(), s47.UEContextModificationRequestIEs().SRVCCOperationPossible().Info(), s47.UEContextModificationRequestIEs().SRVCCOperationNotPossible().Info(), s47.UEContextModificationRequestIEs().V2XServicesAuthorized().Info(), s47.UEContextModificationRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s47.UEContextModificationRequestIEs().NRUESecurityCapabilities().Info(), s47.UEContextModificationRequestIEs().AerialUEsubscriptionInformation().Info(), s47.UEContextModificationRequestIEs().AdditionalRRMPriorityIndex().Info(), s47.UEContextModificationRequestIEs().IABAuthorized().Info(), s47.UEContextModificationRequestIEs().NRV2XServicesAuthorized().Info(), s47.UEContextModificationRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s47.UEContextModificationRequestIEs().PC5QoSParameters().Info(), s47.UEContextModificationRequestIEs().UERadioCapabilityID().Info(), s47.UEContextModificationRequestIEs().TimeRefDistribution().Info()}
			s25.BridgeMergeNestedValidation(report, s47.BridgeUEContextModificationRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(107):
				if value, ok := fields[i].Value.AsUESecurityCapabilities(); ok {
					BridgeWalkValidationUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=107}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(159):
				if value, ok := fields[i].Value.AsRegisteredLAI(); ok {
					s49.BridgeWalkValidationLAI(value, report, fmt.Sprintf("%s[%d]{id=159}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(195):
				if value, ok := fields[i].Value.AsProSeAuthorized(); ok {
					s49.BridgeWalkValidationProSeAuthorized(value, report, fmt.Sprintf("%s[%d]{id=195}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(240):
				if value, ok := fields[i].Value.AsV2XServicesAuthorized(); ok {
					BridgeWalkValidationV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=240}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(248):
				if value, ok := fields[i].Value.AsUESidelinkAggregateMaximumBitrate(); ok {
					BridgeWalkValidationUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=248}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(269):
				if value, ok := fields[i].Value.AsNRUESecurityCapabilities(); ok {
					s49.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(306):
				if value, ok := fields[i].Value.AsNRV2XServicesAuthorized(); ok {
					s49.BridgeWalkValidationNRV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=306}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(307):
				if value, ok := fields[i].Value.AsNRUESidelinkAggregateMaximumBitrate(); ok {
					s49.BridgeWalkValidationNRUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=307}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(308):
				if value, ok := fields[i].Value.AsPC5QoSParameters(); ok {
					s49.BridgeWalkValidationPC5QoSParameters(value, report, fmt.Sprintf("%s[%d]{id=308}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextModificationResponse(v *s36.UEContextModificationResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s23.UEContextModificationResponseIEs().MMEUES1APID().Info(), s23.UEContextModificationResponseIEs().ENBUES1APID().Info(), s23.UEContextModificationResponseIEs().CriticalityDiagnostics().Info()}
			s25.BridgeMergeNestedValidation(report, s36.BridgeUEContextModificationResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextReleaseCommand(v *s37.UEContextReleaseCommand, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s37.UEContextReleaseCommandIEs().UES1APIDs().Info(), s37.UEContextReleaseCommandIEs().Cause().Info()}
			s25.BridgeMergeNestedValidation(report, s37.BridgeUEContextReleaseCommandIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(99):
				if value, ok := fields[i].Value.AsUES1APIDs(); ok {
					BridgeWalkValidationUES1APIDs(value, report, fmt.Sprintf("%s[%d]{id=99}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s49.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextReleaseComplete(v *s46.UEContextReleaseComplete, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s45.UEContextReleaseCompleteIEs().MMEUES1APID().Info(), s45.UEContextReleaseCompleteIEs().ENBUES1APID().Info(), s45.UEContextReleaseCompleteIEs().CriticalityDiagnostics().Info(), s45.UEContextReleaseCompleteIEs().UserLocationInformation().Info(), s45.UEContextReleaseCompleteIEs().InformationOnRecommendedCellsAndENBsForPaging().Info(), s45.UEContextReleaseCompleteIEs().CellIdentifierAndCELevelForCECapableUEs().Info(), s45.UEContextReleaseCompleteIEs().SecondaryRATDataUsageReportList().Info(), s45.UEContextReleaseCompleteIEs().TimeSinceSecondaryNodeRelease().Info()}
			s25.BridgeMergeNestedValidation(report, s46.BridgeUEContextReleaseCompleteIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(213):
				if value, ok := fields[i].Value.AsInformationOnRecommendedCellsAndENBsForPaging(); ok {
					BridgeWalkValidationInformationOnRecommendedCellsAndENBsForPaging(value, report, fmt.Sprintf("%s[%d]{id=213}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(212):
				if value, ok := fields[i].Value.AsCellIdentifierAndCELevelForCECapableUEs(); ok {
					s49.BridgeWalkValidationCellIdentifierAndCELevelForCECapableUEs(value, report, fmt.Sprintf("%s[%d]{id=212}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s49.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextReleaseRequest(v *s43.UEContextReleaseRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s43.UEContextReleaseRequestIEs().MMEUES1APID().Info(), s43.UEContextReleaseRequestIEs().ENBUES1APID().Info(), s43.UEContextReleaseRequestIEs().Cause().Info(), s43.UEContextReleaseRequestIEs().GWContextReleaseIndication().Info(), s43.UEContextReleaseRequestIEs().SecondaryRATDataUsageReportList().Info()}
			s25.BridgeMergeNestedValidation(report, s43.BridgeUEContextReleaseRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s49.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s49.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextResumeFailure(v *s36.UEContextResumeFailure, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s23.UEContextResumeFailureIEs().MMEUES1APID().Info(), s23.UEContextResumeFailureIEs().ENBUES1APID().Info(), s23.UEContextResumeFailureIEs().Cause().Info(), s23.UEContextResumeFailureIEs().CriticalityDiagnostics().Info()}
			s25.BridgeMergeNestedValidation(report, s36.BridgeUEContextResumeFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s49.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextResumeRequest(v *s38.UEContextResumeRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s38.UEContextResumeRequestIEs().MMEUES1APID().Info(), s38.UEContextResumeRequestIEs().ENBUES1APID().Info(), s38.UEContextResumeRequestIEs().ERABFailedToResumeListResumeReq().Info(), s38.UEContextResumeRequestIEs().RRCResumeCause().Info()}
			s25.BridgeMergeNestedValidation(report, s38.BridgeUEContextResumeRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(235):
				if value, ok := fields[i].Value.AsERABFailedToResumeListResumeReq(); ok {
					s49.BridgeWalkValidationERABFailedToResumeListResumeReq(value, report, fmt.Sprintf("%s[%d]{id=235}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextResumeResponse(v *s38.UEContextResumeResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s38.UEContextResumeResponseIEs().MMEUES1APID().Info(), s38.UEContextResumeResponseIEs().ENBUES1APID().Info(), s38.UEContextResumeResponseIEs().ERABFailedToResumeListResumeRes().Info(), s38.UEContextResumeResponseIEs().CriticalityDiagnostics().Info(), s38.UEContextResumeResponseIEs().SecurityContext().Info(), s38.UEContextResumeResponseIEs().PendingDataIndication().Info()}
			s25.BridgeMergeNestedValidation(report, s39.BridgeUEContextResumeResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(237):
				if value, ok := fields[i].Value.AsERABFailedToResumeListResumeRes(); ok {
					s49.BridgeWalkValidationERABFailedToResumeListResumeRes(value, report, fmt.Sprintf("%s[%d]{id=237}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(40):
				if value, ok := fields[i].Value.AsSecurityContext(); ok {
					s49.BridgeWalkValidationSecurityContext(value, report, fmt.Sprintf("%s[%d]{id=40}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextSuspendRequest(v *s46.UEContextSuspendRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s46.UEContextSuspendRequestIEs().MMEUES1APID().Info(), s46.UEContextSuspendRequestIEs().ENBUES1APID().Info(), s46.UEContextSuspendRequestIEs().InformationOnRecommendedCellsAndENBsForPaging().Info(), s46.UEContextSuspendRequestIEs().CellIdentifierAndCELevelForCECapableUEs().Info(), s46.UEContextSuspendRequestIEs().SecondaryRATDataUsageReportList().Info(), s46.UEContextSuspendRequestIEs().UserLocationInformation().Info(), s46.UEContextSuspendRequestIEs().TimeSinceSecondaryNodeRelease().Info()}
			s25.BridgeMergeNestedValidation(report, s46.BridgeUEContextSuspendRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(213):
				if value, ok := fields[i].Value.AsInformationOnRecommendedCellsAndENBsForPaging(); ok {
					BridgeWalkValidationInformationOnRecommendedCellsAndENBsForPaging(value, report, fmt.Sprintf("%s[%d]{id=213}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(212):
				if value, ok := fields[i].Value.AsCellIdentifierAndCELevelForCECapableUEs(); ok {
					s49.BridgeWalkValidationCellIdentifierAndCELevelForCECapableUEs(value, report, fmt.Sprintf("%s[%d]{id=212}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s49.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextSuspendResponse(v *s36.UEContextSuspendResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s28.UEContextSuspendResponseIEs().MMEUES1APID().Info(), s28.UEContextSuspendResponseIEs().ENBUES1APID().Info(), s28.UEContextSuspendResponseIEs().CriticalityDiagnostics().Info(), s28.UEContextSuspendResponseIEs().SecurityContext().Info()}
			s25.BridgeMergeNestedValidation(report, s36.BridgeUEContextSuspendResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(40):
				if value, ok := fields[i].Value.AsSecurityContext(); ok {
					s49.BridgeWalkValidationSecurityContext(value, report, fmt.Sprintf("%s[%d]{id=40}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEHistoryInformation(v *s41.UEHistoryInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s21.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		s49.BridgeWalkValidationLastVisitedCellItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationUEInformationTransfer(v *s36.UEInformationTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s31.UEInformationTransferIEs().STMSI().Info(), s31.UEInformationTransferIEs().UELevelQoSParameters().Info(), s31.UEInformationTransferIEs().UERadioCapability().Info(), s31.UEInformationTransferIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s31.UEInformationTransferIEs().PendingDataIndication().Info(), s31.UEInformationTransferIEs().MaskedIMEISV().Info()}
			s25.BridgeMergeNestedValidation(report, s36.BridgeUEInformationTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(96):
				if value, ok := fields[i].Value.AsSTMSI(); ok {
					s49.BridgeWalkValidationSTMSI(value, report, fmt.Sprintf("%s[%d]{id=96}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(252):
				if value, ok := fields[i].Value.AsUELevelQoSParameters(); ok {
					s49.BridgeWalkValidationERABLevelQoSParameters(value, report, fmt.Sprintf("%s[%d]{id=252}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEPagingID(v *s28.UEPagingID, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.UEPagingIDChoiceSTMSI && v.STMSI != nil {
		s49.BridgeWalkValidationSTMSI(v.STMSI, report, path+".s-TMSI", false)
	}
}
func BridgeWalkValidationUERadioCapabilityIDMappingRequest(v *s36.UERadioCapabilityIDMappingRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s12.UERadioCapabilityIDMappingRequestIEs().UERadioCapabilityID().Info()}
			s25.BridgeMergeNestedValidation(report, s36.BridgeUERadioCapabilityIDMappingRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUERadioCapabilityIDMappingResponse(v *s36.UERadioCapabilityIDMappingResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s24.UERadioCapabilityIDMappingResponseIEs().UERadioCapabilityID().Info(), s24.UERadioCapabilityIDMappingResponseIEs().UERadioCapability().Info(), s24.UERadioCapabilityIDMappingResponseIEs().CriticalityDiagnostics().Info()}
			s25.BridgeMergeNestedValidation(report, s36.BridgeUERadioCapabilityIDMappingResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUERadioCapabilityMatchRequest(v *s36.UERadioCapabilityMatchRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s12.UERadioCapabilityMatchRequestIEs().MMEUES1APID().Info(), s12.UERadioCapabilityMatchRequestIEs().ENBUES1APID().Info(), s12.UERadioCapabilityMatchRequestIEs().UERadioCapability().Info(), s12.UERadioCapabilityMatchRequestIEs().UERadioCapabilityID().Info()}
			s25.BridgeMergeNestedValidation(report, s36.BridgeUERadioCapabilityMatchRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUERadioCapabilityMatchResponse(v *s37.UERadioCapabilityMatchResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s24.UERadioCapabilityMatchResponseIEs().MMEUES1APID().Info(), s24.UERadioCapabilityMatchResponseIEs().ENBUES1APID().Info(), s24.UERadioCapabilityMatchResponseIEs().VoiceSupportMatchIndicator().Info(), s24.UERadioCapabilityMatchResponseIEs().CriticalityDiagnostics().Info()}
			s25.BridgeMergeNestedValidation(report, s37.BridgeUERadioCapabilityMatchResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUES1APIDPair(v *s37.UES1APIDPair, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s37.BridgeUES1APIDPairExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUES1APIDs(v *s37.UES1APIDs, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.UES1APIDsChoiceUES1APIDPair && v.UES1APIDPair != nil {
		BridgeWalkValidationUES1APIDPair(v.UES1APIDPair, report, path+".uE-S1AP-ID-pair", false)
	}
}
func BridgeWalkValidationUESecurityCapabilities(v *s37.UESecurityCapabilities, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s37.BridgeUESecurityCapabilitiesExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUESidelinkAggregateMaximumBitrate(v *s37.UESidelinkAggregateMaximumBitrate, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s37.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationULCPSecurityInformation(v *s37.ULCPSecurityInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s37.BridgeULCPSecurityInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUnsuccessfulOutcome(v *s36.UnsuccessfulOutcome, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUplinkNASTransport(v *s44.UplinkNASTransport, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s32.UplinkNASTransportIEs().MMEUES1APID().Info(), s32.UplinkNASTransportIEs().ENBUES1APID().Info(), s32.UplinkNASTransportIEs().NASPDU().Info(), s32.UplinkNASTransportIEs().EUTRANCGI().Info(), s32.UplinkNASTransportIEs().TAI().Info(), s32.UplinkNASTransportIEs().GWTransportLayerAddress().Info(), s32.UplinkNASTransportIEs().SIPTOLGWTransportLayerAddress().Info(), s32.UplinkNASTransportIEs().LHNID().Info(), s32.UplinkNASTransportIEs().PSCellInformation().Info(), s32.UplinkNASTransportIEs().LTENTNTAIInformation().Info()}
			s25.BridgeMergeNestedValidation(report, s44.BridgeUplinkNASTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					s49.BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(288):
				if value, ok := fields[i].Value.AsPSCellInformation(); ok {
					s49.BridgeWalkValidationPSCellInformation(value, report, fmt.Sprintf("%s[%d]{id=288}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUplinkNonUEAssociatedLPPaTransport(v *s44.UplinkNonUEAssociatedLPPaTransport, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s12.UplinkNonUEAssociatedLPPaTransportIEs().RoutingID().Info(), s12.UplinkNonUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
			s25.BridgeMergeNestedValidation(report, s44.BridgeUplinkNonUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUplinkS1cdma2000tunnelling(v *s44.UplinkS1cdma2000tunnelling, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s21.UplinkS1cdma2000tunnellingIEs().MMEUES1APID().Info(), s21.UplinkS1cdma2000tunnellingIEs().ENBUES1APID().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000RATType().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000SectorID().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000HORequiredIndication().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000OneXSRVCCInfo().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000OneXRAND().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000PDU().Info(), s21.UplinkS1cdma2000tunnellingIEs().EUTRANRoundTripDelayEstimationInfo().Info()}
			s25.BridgeMergeNestedValidation(report, s44.BridgeUplinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(102):
				if value, ok := fields[i].Value.AsCdma2000OneXSRVCCInfo(); ok {
					s49.BridgeWalkValidationCdma2000OneXSRVCCInfo(value, report, fmt.Sprintf("%s[%d]{id=102}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUplinkUEAssociatedLPPaTransport(v *s44.UplinkUEAssociatedLPPaTransport, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s12.UplinkUEAssociatedLPPaTransportIEs().MMEUES1APID().Info(), s12.UplinkUEAssociatedLPPaTransportIEs().ENBUES1APID().Info(), s12.UplinkUEAssociatedLPPaTransportIEs().RoutingID().Info(), s12.UplinkUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
			s25.BridgeMergeNestedValidation(report, s44.BridgeUplinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUserLocationInformation(v *s44.UserLocationInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s49.BridgeWalkValidationEUTRANCGI(&v.EutranCgi, report, path+".eutran-cgi", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationTAI(&v.Tai, report, path+".tai", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s21.UserLocationInformationExtIEs().PSCellInformation().Info()), s00.FieldInfo(s21.UserLocationInformationExtIEs().LTENTNTAIInformation().Info())}
				s25.BridgeMergeNestedValidation(report, s46.BridgeUserLocationInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(288):
					if value, ok := fields[i].ExtensionValue.AsPSCellInformation(); ok {
						s49.BridgeWalkValidationPSCellInformation(value, report, fmt.Sprintf("%s[%d]{id=288}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(339):
					if value, ok := fields[i].ExtensionValue.AsLTENTNTAIInformation(); ok {
						BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationV2XServicesAuthorized(v *s46.V2XServicesAuthorized, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s47.BridgeV2XServicesAuthorizedExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationWLANMeasConfigNameList(v *s00.WLANMeasConfigNameList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationWLANMeasurementConfiguration(v *s47.WLANMeasurementConfiguration, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.WlanMeasConfigNameList != nil {
		BridgeWalkValidationWLANMeasConfigNameList(&v.WlanMeasConfigNameList, report, path+".wlanMeasConfigNameList", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s49.BridgeWLANMeasurementConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationWUSAssistanceInformation(v *s49.WUSAssistanceInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s25.BridgeMergeNestedValidation(report, s49.BridgeWUSAssistanceInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationWarningAreaList(v *s32.WarningAreaList, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.WarningAreaListChoiceCellIDList && v.CellIDList != nil {
		s49.BridgeWalkValidationECGIList(&v.CellIDList, report, path+".cellIDList", false)
	}
	if v.Choice == s00.WarningAreaListChoiceTrackingAreaListforWarning && v.TrackingAreaListforWarning != nil {
		BridgeWalkValidationTAIListforWarning(&v.TrackingAreaListforWarning, report, path+".trackingAreaListforWarning", false)
	}
	if v.Choice == s00.WarningAreaListChoiceEmergencyAreaIDList && v.EmergencyAreaIDList != nil {
		s49.BridgeWalkValidationEmergencyAreaIDList(&v.EmergencyAreaIDList, report, path+".emergencyAreaIDList", false)
	}
}
func BridgeWalkValidationWriteReplaceWarningRequest(v *WriteReplaceWarningRequest, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s33.WriteReplaceWarningRequestIEs().MessageIdentifier().Info(), s33.WriteReplaceWarningRequestIEs().SerialNumber().Info(), s33.WriteReplaceWarningRequestIEs().WarningAreaList().Info(), s33.WriteReplaceWarningRequestIEs().RepetitionPeriod().Info(), s33.WriteReplaceWarningRequestIEs().ExtendedRepetitionPeriod().Info(), s33.WriteReplaceWarningRequestIEs().NumberofBroadcastRequest().Info(), s33.WriteReplaceWarningRequestIEs().WarningType().Info(), s33.WriteReplaceWarningRequestIEs().WarningSecurityInfo().Info(), s33.WriteReplaceWarningRequestIEs().DataCodingScheme().Info(), s33.WriteReplaceWarningRequestIEs().WarningMessageContents().Info(), s33.WriteReplaceWarningRequestIEs().ConcurrentWarningMessageIndicator().Info(), s33.WriteReplaceWarningRequestIEs().WarningAreaCoordinates().Info()}
			s25.BridgeMergeNestedValidation(report, BridgeWriteReplaceWarningRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(113):
				if value, ok := fields[i].Value.AsWarningAreaList(); ok {
					BridgeWalkValidationWarningAreaList(value, report, fmt.Sprintf("%s[%d]{id=113}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationWriteReplaceWarningResponse(v *WriteReplaceWarningResponse, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s32.WriteReplaceWarningResponseIEs().MessageIdentifier().Info(), s32.WriteReplaceWarningResponseIEs().SerialNumber().Info(), s32.WriteReplaceWarningResponseIEs().BroadcastCompletedAreaList().Info(), s32.WriteReplaceWarningResponseIEs().CriticalityDiagnostics().Info()}
			s25.BridgeMergeNestedValidation(report, BridgeWriteReplaceWarningResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(120):
				if value, ok := fields[i].Value.AsBroadcastCompletedAreaList(); ok {
					BridgeWalkValidationBroadcastCompletedAreaList(value, report, fmt.Sprintf("%s[%d]{id=120}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s49.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldCapture(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *func(s24.ENBConfigurationUpdateAcknowledge, aper.DecodeState) (s24.ENBConfigurationUpdateAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldCompare(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *func(s24.ENBConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldContext(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldDecode(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *func([]byte, aper.DecodeState) (s24.ENBConfigurationUpdateAcknowledge, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldEncode(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *func(*s24.ENBConfigurationUpdateAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldInfo(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldInject(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *func(s24.ENBConfigurationUpdateAcknowledge) SuccessfulValue {
	return &v.inject
}
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldValidate(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *func(*s24.ENBConfigurationUpdateAcknowledge, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeERABModificationConfirmSuccessfulBindingFieldCapture(v *ERABModificationConfirmSuccessfulBinding) *func(s39.ERABModificationConfirm, aper.DecodeState) (s39.ERABModificationConfirm, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModificationConfirmSuccessfulBindingFieldCompare(v *ERABModificationConfirmSuccessfulBinding) *func(s39.ERABModificationConfirm, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModificationConfirmSuccessfulBindingFieldContext(v *ERABModificationConfirmSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationConfirmSuccessfulBindingFieldDecode(v *ERABModificationConfirmSuccessfulBinding) *func([]byte, aper.DecodeState) (s39.ERABModificationConfirm, error) {
	return &v.decode
}
func BridgeERABModificationConfirmSuccessfulBindingFieldEncode(v *ERABModificationConfirmSuccessfulBinding) *func(*s39.ERABModificationConfirm, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModificationConfirmSuccessfulBindingFieldInfo(v *ERABModificationConfirmSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeERABModificationConfirmSuccessfulBindingFieldInject(v *ERABModificationConfirmSuccessfulBinding) *func(s39.ERABModificationConfirm) SuccessfulValue {
	return &v.inject
}
func BridgeERABModificationConfirmSuccessfulBindingFieldValidate(v *ERABModificationConfirmSuccessfulBinding) *func(*s39.ERABModificationConfirm, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeERABModifyResponseSuccessfulBindingFieldCapture(v *ERABModifyResponseSuccessfulBinding) *func(s46.ERABModifyResponse, aper.DecodeState) (s46.ERABModifyResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyResponseSuccessfulBindingFieldCompare(v *ERABModifyResponseSuccessfulBinding) *func(s46.ERABModifyResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyResponseSuccessfulBindingFieldContext(v *ERABModifyResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyResponseSuccessfulBindingFieldDecode(v *ERABModifyResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s46.ERABModifyResponse, error) {
	return &v.decode
}
func BridgeERABModifyResponseSuccessfulBindingFieldEncode(v *ERABModifyResponseSuccessfulBinding) *func(*s46.ERABModifyResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyResponseSuccessfulBindingFieldInfo(v *ERABModifyResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeERABModifyResponseSuccessfulBindingFieldInject(v *ERABModifyResponseSuccessfulBinding) *func(s46.ERABModifyResponse) SuccessfulValue {
	return &v.inject
}
func BridgeERABModifyResponseSuccessfulBindingFieldValidate(v *ERABModifyResponseSuccessfulBinding) *func(*s46.ERABModifyResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeERABReleaseResponseSuccessfulBindingFieldCapture(v *ERABReleaseResponseSuccessfulBinding) *func(s46.ERABReleaseResponse, aper.DecodeState) (s46.ERABReleaseResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseResponseSuccessfulBindingFieldCompare(v *ERABReleaseResponseSuccessfulBinding) *func(s46.ERABReleaseResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseResponseSuccessfulBindingFieldContext(v *ERABReleaseResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseResponseSuccessfulBindingFieldDecode(v *ERABReleaseResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s46.ERABReleaseResponse, error) {
	return &v.decode
}
func BridgeERABReleaseResponseSuccessfulBindingFieldEncode(v *ERABReleaseResponseSuccessfulBinding) *func(*s46.ERABReleaseResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseResponseSuccessfulBindingFieldInfo(v *ERABReleaseResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeERABReleaseResponseSuccessfulBindingFieldInject(v *ERABReleaseResponseSuccessfulBinding) *func(s46.ERABReleaseResponse) SuccessfulValue {
	return &v.inject
}
func BridgeERABReleaseResponseSuccessfulBindingFieldValidate(v *ERABReleaseResponseSuccessfulBinding) *func(*s46.ERABReleaseResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeERABSetupResponseSuccessfulBindingFieldCapture(v *ERABSetupResponseSuccessfulBinding) *func(s46.ERABSetupResponse, aper.DecodeState) (s46.ERABSetupResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupResponseSuccessfulBindingFieldCompare(v *ERABSetupResponseSuccessfulBinding) *func(s46.ERABSetupResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupResponseSuccessfulBindingFieldContext(v *ERABSetupResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseSuccessfulBindingFieldDecode(v *ERABSetupResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s46.ERABSetupResponse, error) {
	return &v.decode
}
func BridgeERABSetupResponseSuccessfulBindingFieldEncode(v *ERABSetupResponseSuccessfulBinding) *func(*s46.ERABSetupResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupResponseSuccessfulBindingFieldInfo(v *ERABSetupResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeERABSetupResponseSuccessfulBindingFieldInject(v *ERABSetupResponseSuccessfulBinding) *func(s46.ERABSetupResponse) SuccessfulValue {
	return &v.inject
}
func BridgeERABSetupResponseSuccessfulBindingFieldValidate(v *ERABSetupResponseSuccessfulBinding) *func(*s46.ERABSetupResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldCapture(v *HandoverCancelAcknowledgeSuccessfulBinding) *func(s25.HandoverCancelAcknowledge, aper.DecodeState) (s25.HandoverCancelAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldCompare(v *HandoverCancelAcknowledgeSuccessfulBinding) *func(s25.HandoverCancelAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldContext(v *HandoverCancelAcknowledgeSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldDecode(v *HandoverCancelAcknowledgeSuccessfulBinding) *func([]byte, aper.DecodeState) (s25.HandoverCancelAcknowledge, error) {
	return &v.decode
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldEncode(v *HandoverCancelAcknowledgeSuccessfulBinding) *func(*s25.HandoverCancelAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldInfo(v *HandoverCancelAcknowledgeSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldInject(v *HandoverCancelAcknowledgeSuccessfulBinding) *func(s25.HandoverCancelAcknowledge) SuccessfulValue {
	return &v.inject
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldValidate(v *HandoverCancelAcknowledgeSuccessfulBinding) *func(*s25.HandoverCancelAcknowledge, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeHandoverCommandSuccessfulBindingFieldCapture(v *HandoverCommandSuccessfulBinding) *func(s40.HandoverCommand, aper.DecodeState) (s40.HandoverCommand, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCommandSuccessfulBindingFieldCompare(v *HandoverCommandSuccessfulBinding) *func(s40.HandoverCommand, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCommandSuccessfulBindingFieldContext(v *HandoverCommandSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCommandSuccessfulBindingFieldDecode(v *HandoverCommandSuccessfulBinding) *func([]byte, aper.DecodeState) (s40.HandoverCommand, error) {
	return &v.decode
}
func BridgeHandoverCommandSuccessfulBindingFieldEncode(v *HandoverCommandSuccessfulBinding) *func(*s40.HandoverCommand, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCommandSuccessfulBindingFieldInfo(v *HandoverCommandSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeHandoverCommandSuccessfulBindingFieldInject(v *HandoverCommandSuccessfulBinding) *func(s40.HandoverCommand) SuccessfulValue {
	return &v.inject
}
func BridgeHandoverCommandSuccessfulBindingFieldValidate(v *HandoverCommandSuccessfulBinding) *func(*s40.HandoverCommand, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldCapture(v *HandoverRequestAcknowledgeSuccessfulBinding) *func(s39.HandoverRequestAcknowledge, aper.DecodeState) (s39.HandoverRequestAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldCompare(v *HandoverRequestAcknowledgeSuccessfulBinding) *func(s39.HandoverRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldContext(v *HandoverRequestAcknowledgeSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldDecode(v *HandoverRequestAcknowledgeSuccessfulBinding) *func([]byte, aper.DecodeState) (s39.HandoverRequestAcknowledge, error) {
	return &v.decode
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldEncode(v *HandoverRequestAcknowledgeSuccessfulBinding) *func(*s39.HandoverRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldInfo(v *HandoverRequestAcknowledgeSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldInject(v *HandoverRequestAcknowledgeSuccessfulBinding) *func(s39.HandoverRequestAcknowledge) SuccessfulValue {
	return &v.inject
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldValidate(v *HandoverRequestAcknowledgeSuccessfulBinding) *func(*s39.HandoverRequestAcknowledge, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldCapture(v *InitialContextSetupResponseSuccessfulBinding) *func(s40.InitialContextSetupResponse, aper.DecodeState) (s40.InitialContextSetupResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldCompare(v *InitialContextSetupResponseSuccessfulBinding) *func(s40.InitialContextSetupResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldContext(v *InitialContextSetupResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldDecode(v *InitialContextSetupResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s40.InitialContextSetupResponse, error) {
	return &v.decode
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldEncode(v *InitialContextSetupResponseSuccessfulBinding) *func(*s40.InitialContextSetupResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldInfo(v *InitialContextSetupResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldInject(v *InitialContextSetupResponseSuccessfulBinding) *func(s40.InitialContextSetupResponse) SuccessfulValue {
	return &v.inject
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldValidate(v *InitialContextSetupResponseSuccessfulBinding) *func(*s40.InitialContextSetupResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeKillResponseSuccessfulBindingFieldCapture(v *KillResponseSuccessfulBinding) *func(s33.KillResponse, aper.DecodeState) (s33.KillResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeKillResponseSuccessfulBindingFieldCompare(v *KillResponseSuccessfulBinding) *func(s33.KillResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillResponseSuccessfulBindingFieldContext(v *KillResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseSuccessfulBindingFieldDecode(v *KillResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s33.KillResponse, error) {
	return &v.decode
}
func BridgeKillResponseSuccessfulBindingFieldEncode(v *KillResponseSuccessfulBinding) *func(*s33.KillResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillResponseSuccessfulBindingFieldInfo(v *KillResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeKillResponseSuccessfulBindingFieldInject(v *KillResponseSuccessfulBinding) *func(s33.KillResponse) SuccessfulValue {
	return &v.inject
}
func BridgeKillResponseSuccessfulBindingFieldValidate(v *KillResponseSuccessfulBinding) *func(*s33.KillResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldCapture(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *func(s25.MMEConfigurationUpdateAcknowledge, aper.DecodeState) (s25.MMEConfigurationUpdateAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldCompare(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *func(s25.MMEConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldContext(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldDecode(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *func([]byte, aper.DecodeState) (s25.MMEConfigurationUpdateAcknowledge, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldEncode(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *func(*s25.MMEConfigurationUpdateAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldInfo(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldInject(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *func(s25.MMEConfigurationUpdateAcknowledge) SuccessfulValue {
	return &v.inject
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldValidate(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *func(*s25.MMEConfigurationUpdateAcknowledge, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldCapture(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func(s47.PathSwitchRequestAcknowledge, aper.DecodeState) (s47.PathSwitchRequestAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldCompare(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func(s47.PathSwitchRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldContext(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldDecode(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func([]byte, aper.DecodeState) (s47.PathSwitchRequestAcknowledge, error) {
	return &v.decode
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldEncode(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func(*s47.PathSwitchRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldInfo(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldInject(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func(s47.PathSwitchRequestAcknowledge) SuccessfulValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldValidate(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func(*s47.PathSwitchRequestAcknowledge, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeResetAcknowledgeSuccessfulBindingFieldCapture(v *ResetAcknowledgeSuccessfulBinding) *func(s44.ResetAcknowledge, aper.DecodeState) (s44.ResetAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeResetAcknowledgeSuccessfulBindingFieldCompare(v *ResetAcknowledgeSuccessfulBinding) *func(s44.ResetAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetAcknowledgeSuccessfulBindingFieldContext(v *ResetAcknowledgeSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeSuccessfulBindingFieldDecode(v *ResetAcknowledgeSuccessfulBinding) *func([]byte, aper.DecodeState) (s44.ResetAcknowledge, error) {
	return &v.decode
}
func BridgeResetAcknowledgeSuccessfulBindingFieldEncode(v *ResetAcknowledgeSuccessfulBinding) *func(*s44.ResetAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetAcknowledgeSuccessfulBindingFieldInfo(v *ResetAcknowledgeSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeResetAcknowledgeSuccessfulBindingFieldInject(v *ResetAcknowledgeSuccessfulBinding) *func(s44.ResetAcknowledge) SuccessfulValue {
	return &v.inject
}
func BridgeResetAcknowledgeSuccessfulBindingFieldValidate(v *ResetAcknowledgeSuccessfulBinding) *func(*s44.ResetAcknowledge, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeS1RemovalResponseSuccessfulBindingFieldCapture(v *S1RemovalResponseSuccessfulBinding) *func(s26.S1RemovalResponse, aper.DecodeState) (s26.S1RemovalResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalResponseSuccessfulBindingFieldCompare(v *S1RemovalResponseSuccessfulBinding) *func(s26.S1RemovalResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalResponseSuccessfulBindingFieldContext(v *S1RemovalResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalResponseSuccessfulBindingFieldDecode(v *S1RemovalResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s26.S1RemovalResponse, error) {
	return &v.decode
}
func BridgeS1RemovalResponseSuccessfulBindingFieldEncode(v *S1RemovalResponseSuccessfulBinding) *func(*s26.S1RemovalResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalResponseSuccessfulBindingFieldInfo(v *S1RemovalResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1RemovalResponseSuccessfulBindingFieldInject(v *S1RemovalResponseSuccessfulBinding) *func(s26.S1RemovalResponse) SuccessfulValue {
	return &v.inject
}
func BridgeS1RemovalResponseSuccessfulBindingFieldValidate(v *S1RemovalResponseSuccessfulBinding) *func(*s26.S1RemovalResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeS1SetupResponseSuccessfulBindingFieldCapture(v *S1SetupResponseSuccessfulBinding) *func(s43.S1SetupResponse, aper.DecodeState) (s43.S1SetupResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupResponseSuccessfulBindingFieldCompare(v *S1SetupResponseSuccessfulBinding) *func(s43.S1SetupResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupResponseSuccessfulBindingFieldContext(v *S1SetupResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupResponseSuccessfulBindingFieldDecode(v *S1SetupResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s43.S1SetupResponse, error) {
	return &v.decode
}
func BridgeS1SetupResponseSuccessfulBindingFieldEncode(v *S1SetupResponseSuccessfulBinding) *func(*s43.S1SetupResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupResponseSuccessfulBindingFieldInfo(v *S1SetupResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1SetupResponseSuccessfulBindingFieldInject(v *S1SetupResponseSuccessfulBinding) *func(s43.S1SetupResponse) SuccessfulValue {
	return &v.inject
}
func BridgeS1SetupResponseSuccessfulBindingFieldValidate(v *S1SetupResponseSuccessfulBinding) *func(*s43.S1SetupResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeSONConfigurationTransferExtIEsExtContainerAPERValueFieldContext(v *SONConfigurationTransferExtIEsExtContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONConfigurationTransferExtIEsExtContainerAPERValueFieldReceived(v *SONConfigurationTransferExtIEsExtContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONConfigurationTransferExtIEsExtContainerAPERValueFieldReplay(v *SONConfigurationTransferExtIEsExtContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONConfigurationTransferExtIEsExtContainerAPERValueFieldWithoutReplay(v *SONConfigurationTransferExtIEsExtContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSONConfigurationTransferExtIEsExtContainerValueCodecFieldCapture(v *SONConfigurationTransferExtIEsExtContainerValueCodec) *func(SONConfigurationTransferExtIEsExtContainer, aper.DecodeState) (SONConfigurationTransferExtIEsExtContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSONConfigurationTransferExtIEsExtContainerValueCodecFieldCompare(v *SONConfigurationTransferExtIEsExtContainerValueCodec) *func(SONConfigurationTransferExtIEsExtContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONConfigurationTransferExtIEsExtContainerValueCodecFieldContext(v *SONConfigurationTransferExtIEsExtContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONConfigurationTransferExtIEsExtContainerValueCodecFieldDecode(v *SONConfigurationTransferExtIEsExtContainerValueCodec) *func([]byte, aper.DecodeState) (SONConfigurationTransferExtIEsExtContainer, error) {
	return &v.decode
}
func BridgeSONConfigurationTransferExtIEsExtContainerValueCodecFieldEncode(v *SONConfigurationTransferExtIEsExtContainerValueCodec) *func(SONConfigurationTransferExtIEsExtContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONConfigurationTransferExtIEsExtContainerValueCodecFieldPath(v *SONConfigurationTransferExtIEsExtContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONConfigurationTransferExtIEsExtContainerValueCodecMethodEncodeBudgetValue(v SONConfigurationTransferExtIEsExtContainerValueCodec, a0 SONConfigurationTransferExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONConfigurationTransferExtIEsExtContainerValueCodecMethodEncodeChanged(v SONConfigurationTransferExtIEsExtContainerValueCodec, a0 SONConfigurationTransferExtIEsExtContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONConfigurationTransferExtIEsExtFieldAPERValueFieldContext(v *SONConfigurationTransferExtIEsExtFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONConfigurationTransferExtIEsExtFieldAPERValueFieldReceived(v *SONConfigurationTransferExtIEsExtFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONConfigurationTransferExtIEsExtFieldAPERValueFieldReplay(v *SONConfigurationTransferExtIEsExtFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONConfigurationTransferExtIEsExtFieldAPERValueFieldWithoutReplay(v *SONConfigurationTransferExtIEsExtFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSONConfigurationTransferExtIEsExtFieldFieldReceived(v *SONConfigurationTransferExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeSONConfigurationTransferExtIEsExtFieldFieldReplay(v *SONConfigurationTransferExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeSONConfigurationTransferExtIEsExtFieldFieldStream(v *SONConfigurationTransferExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeSONConfigurationTransferExtIEsExtFieldFieldWithoutReplay(v *SONConfigurationTransferExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeSONConfigurationTransferExtIEsExtFieldMethodMarshalAPERTo(v *SONConfigurationTransferExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSONConfigurationTransferExtIEsExtFieldMethodUnmarshalAPERFrom(v *SONConfigurationTransferExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSONConfigurationTransferExtIEsExtFieldValueCodecFieldCapture(v *SONConfigurationTransferExtIEsExtFieldValueCodec) *func(SONConfigurationTransferExtIEsExtField, aper.DecodeState) (SONConfigurationTransferExtIEsExtField, aper.Snapshot) {
	return &v.capture
}
func BridgeSONConfigurationTransferExtIEsExtFieldValueCodecFieldCompare(v *SONConfigurationTransferExtIEsExtFieldValueCodec) *func(SONConfigurationTransferExtIEsExtField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONConfigurationTransferExtIEsExtFieldValueCodecFieldContext(v *SONConfigurationTransferExtIEsExtFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONConfigurationTransferExtIEsExtFieldValueCodecFieldDecode(v *SONConfigurationTransferExtIEsExtFieldValueCodec) *func([]byte, aper.DecodeState) (SONConfigurationTransferExtIEsExtField, error) {
	return &v.decode
}
func BridgeSONConfigurationTransferExtIEsExtFieldValueCodecFieldEncode(v *SONConfigurationTransferExtIEsExtFieldValueCodec) *func(SONConfigurationTransferExtIEsExtField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONConfigurationTransferExtIEsExtFieldValueCodecFieldPath(v *SONConfigurationTransferExtIEsExtFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONConfigurationTransferExtIEsExtFieldValueCodecMethodEncodeBudgetValue(v SONConfigurationTransferExtIEsExtFieldValueCodec, a0 SONConfigurationTransferExtIEsExtField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONConfigurationTransferExtIEsExtFieldValueCodecMethodEncodeChanged(v SONConfigurationTransferExtIEsExtFieldValueCodec, a0 SONConfigurationTransferExtIEsExtField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONConfigurationTransferExtIEsIEFieldFieldReceived(v *SONConfigurationTransferExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeSONConfigurationTransferExtIEsIEFieldFieldReplay(v *SONConfigurationTransferExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeSONConfigurationTransferExtIEsIEFieldFieldStream(v *SONConfigurationTransferExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeSONConfigurationTransferExtIEsIEFieldFieldWithoutReplay(v *SONConfigurationTransferExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeSONConfigurationTransferExtIEsIEFieldMethodMarshalAPERTo(v *SONConfigurationTransferExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSONConfigurationTransferExtIEsIEFieldMethodUnmarshalAPERFrom(v *SONConfigurationTransferExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSONConfigurationTransferExtIEsRequestedTNLInfoExtBindingFieldCodec(v *SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding) *s26.RequestedTNLInfoValueCodec {
	return &v.codec
}
func BridgeSONConfigurationTransferExtIEsRequestedTNLInfoExtBindingFieldGet(v *SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding) *func(*SONConfigurationTransferExtIEsValue) (*s26.RequestedTNLInfo, bool) {
	return &v.get
}
func BridgeSONConfigurationTransferExtIEsRequestedTNLInfoExtBindingFieldInfo(v *SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSONConfigurationTransferExtIEsRequestedTNLInfoExtBindingFieldInject(v *SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding) *func(s26.RequestedTNLInfo) SONConfigurationTransferExtIEsValue {
	return &v.inject
}
func BridgeSONConfigurationTransferExtIEsSynchronisationInformationExtBindingFieldCodec(v *SONConfigurationTransferExtIEsSynchronisationInformationExtBinding) *s31.SynchronisationInformationValueCodec {
	return &v.codec
}
func BridgeSONConfigurationTransferExtIEsSynchronisationInformationExtBindingFieldGet(v *SONConfigurationTransferExtIEsSynchronisationInformationExtBinding) *func(*SONConfigurationTransferExtIEsValue) (*s31.SynchronisationInformation, bool) {
	return &v.get
}
func BridgeSONConfigurationTransferExtIEsSynchronisationInformationExtBindingFieldInfo(v *SONConfigurationTransferExtIEsSynchronisationInformationExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSONConfigurationTransferExtIEsSynchronisationInformationExtBindingFieldInject(v *SONConfigurationTransferExtIEsSynchronisationInformationExtBinding) *func(s31.SynchronisationInformation) SONConfigurationTransferExtIEsValue {
	return &v.inject
}
func BridgeSONConfigurationTransferExtIEsValueFieldId(v *SONConfigurationTransferExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeSONConfigurationTransferExtIEsValueFieldIsOpaque(v *SONConfigurationTransferExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeSONConfigurationTransferExtIEsValueFieldOpaque(v *SONConfigurationTransferExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeSONConfigurationTransferExtIEsValueFieldReceived(v *SONConfigurationTransferExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONConfigurationTransferExtIEsValueFieldReplay(v *SONConfigurationTransferExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONConfigurationTransferExtIEsValueFieldRowRequestedTNLInfo(v *SONConfigurationTransferExtIEsValue) **s26.RequestedTNLInfo {
	return &v.rowRequestedTNLInfo
}
func BridgeSONConfigurationTransferExtIEsValueFieldRowSynchronisationInformation(v *SONConfigurationTransferExtIEsValue) **s31.SynchronisationInformation {
	return &v.rowSynchronisationInformation
}
func BridgeSONConfigurationTransferExtIEsValueFieldRowX2TNLConfigurationInfo(v *SONConfigurationTransferExtIEsValue) **X2TNLConfigurationInfo {
	return &v.rowX2TNLConfigurationInfo
}
func BridgeSONConfigurationTransferExtIEsValueMethodCaptureSemantics(v SONConfigurationTransferExtIEsValue, a0 aper.SemanticCapture) SONConfigurationTransferExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeSONConfigurationTransferExtIEsValueMethodCompareSemantics(v SONConfigurationTransferExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeSONConfigurationTransferExtIEsValueMethodDecode(v SONConfigurationTransferExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (SONConfigurationTransferExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeSONConfigurationTransferExtIEsValueMethodEncode(v SONConfigurationTransferExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeSONConfigurationTransferExtIEsValueMethodEncodeFresh(v SONConfigurationTransferExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeSONConfigurationTransferExtIEsValueMethodMatchesID(v SONConfigurationTransferExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeSONConfigurationTransferExtIEsValueMethodReason(v SONConfigurationTransferExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeSONConfigurationTransferExtIEsValueMethodRule(v SONConfigurationTransferExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeSONInformationReplyFieldExtCount(v *SONInformationReply) *int64   { return &v.extCount }
func BridgeSONInformationReplyFieldExtData(v *SONInformationReply) *[][]byte { return &v.extData }
func BridgeSONInformationReplyFieldExtOrigin(v *SONInformationReply) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSONInformationReplyFieldExtPresent(v *SONInformationReply) *[]bool { return &v.extPresent }
func BridgeSONInformationReplyFieldExtWire(v *SONInformationReply) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeSONInformationReplyFieldIEExtensionsIndef(v *SONInformationReply) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSONInformationReplyFieldPerExtPadding(v *SONInformationReply) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSONInformationReplyFieldPerPadding(v *SONInformationReply) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSONInformationReplyFieldReceived(v *SONInformationReply) *bool { return &v.received }
func BridgeSONInformationReplyFieldReceivedAbsolute(v *SONInformationReply) *bool {
	return &v.receivedAbsolute
}
func BridgeSONInformationReplyFieldReceivedBytes(v *SONInformationReply) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSONInformationReplyFieldReceivedLocation(v *SONInformationReply) *aper.Location {
	return &v.receivedLocation
}
func BridgeSONInformationReplyFieldReplay(v *SONInformationReply) *aper.Snapshot { return &v.replay }
func BridgeSONInformationReplyFieldStream(v *SONInformationReply) *aper.WireSpan { return &v.stream }
func BridgeSONInformationReplyFieldWithoutReplay(v *SONInformationReply) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationReplyMethodMarshalAPERBudget(v *SONInformationReply, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSONInformationReplyMethodMarshalAPERBudgetValue(v *SONInformationReply, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSONInformationReplyMethodMarshalAPERChanged(v *SONInformationReply, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSONInformationReplyMethodMarshalAPERChangedValue(v *SONInformationReply, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSONInformationReplyMethodMarshalAPERLegacy(v *SONInformationReply) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSONInformationReplyMethodMarshalAPERNewValue(v *SONInformationReply, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSONInformationReplyMethodMarshalAPERPlanned(v *SONInformationReply, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSONInformationReplyMethodMarshalAPERTo(v *SONInformationReply, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSONInformationReplyMethodUnmarshalAPERFrom(v *SONInformationReply, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSONInformationReplyMethodUnmarshalAPERLegacy(v *SONInformationReply, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSONInformationReplyMethodUnmarshalAPERWithOptions(v *SONInformationReply, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSuccessfulOutcomeAPERValueFieldContext(v *SuccessfulOutcomeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSuccessfulOutcomeAPERValueFieldReceived(v *SuccessfulOutcomeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSuccessfulOutcomeAPERValueFieldReplay(v *SuccessfulOutcomeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSuccessfulOutcomeAPERValueFieldWithoutReplay(v *SuccessfulOutcomeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSuccessfulOutcomeFieldPerPadding(v *SuccessfulOutcome) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSuccessfulOutcomeFieldReceived(v *SuccessfulOutcome) *bool { return &v.received }
func BridgeSuccessfulOutcomeFieldReceivedAbsolute(v *SuccessfulOutcome) *bool {
	return &v.receivedAbsolute
}
func BridgeSuccessfulOutcomeFieldReceivedBytes(v *SuccessfulOutcome) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSuccessfulOutcomeFieldReceivedLocation(v *SuccessfulOutcome) *aper.Location {
	return &v.receivedLocation
}
func BridgeSuccessfulOutcomeFieldReplay(v *SuccessfulOutcome) *aper.Snapshot { return &v.replay }
func BridgeSuccessfulOutcomeFieldStream(v *SuccessfulOutcome) *aper.WireSpan { return &v.stream }
func BridgeSuccessfulOutcomeFieldWithoutReplay(v *SuccessfulOutcome) *bool   { return &v.withoutReplay }
func BridgeSuccessfulOutcomeMethodMarshalAPERBudget(v *SuccessfulOutcome, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERBudgetValue(v *SuccessfulOutcome, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERChanged(v *SuccessfulOutcome, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERChangedValue(v *SuccessfulOutcome, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERLegacy(v *SuccessfulOutcome) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSuccessfulOutcomeMethodMarshalAPERNewValue(v *SuccessfulOutcome, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERPlanned(v *SuccessfulOutcome, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERTo(v *SuccessfulOutcome, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSuccessfulOutcomeMethodUnmarshalAPERFrom(v *SuccessfulOutcome, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSuccessfulOutcomeMethodUnmarshalAPERLegacy(v *SuccessfulOutcome, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSuccessfulOutcomeMethodUnmarshalAPERWithOptions(v *SuccessfulOutcome, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSuccessfulOutcomeValueCodecFieldCapture(v *SuccessfulOutcomeValueCodec) *func(SuccessfulOutcome, aper.DecodeState) (SuccessfulOutcome, aper.Snapshot) {
	return &v.capture
}
func BridgeSuccessfulOutcomeValueCodecFieldCompare(v *SuccessfulOutcomeValueCodec) *func(SuccessfulOutcome, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSuccessfulOutcomeValueCodecFieldContext(v *SuccessfulOutcomeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSuccessfulOutcomeValueCodecFieldDecode(v *SuccessfulOutcomeValueCodec) *func([]byte, aper.DecodeState) (SuccessfulOutcome, error) {
	return &v.decode
}
func BridgeSuccessfulOutcomeValueCodecFieldEncode(v *SuccessfulOutcomeValueCodec) *func(SuccessfulOutcome, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSuccessfulOutcomeValueCodecFieldPath(v *SuccessfulOutcomeValueCodec) *aper.Path {
	return &v.path
}
func BridgeSuccessfulOutcomeValueCodecMethodEncodeBudgetValue(v SuccessfulOutcomeValueCodec, a0 SuccessfulOutcome, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSuccessfulOutcomeValueCodecMethodEncodeChanged(v SuccessfulOutcomeValueCodec, a0 SuccessfulOutcome, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSuccessfulValueFieldBodyENBConfigurationUpdateAcknowledge(v *SuccessfulValue) **s24.ENBConfigurationUpdateAcknowledge {
	return &v.bodyENBConfigurationUpdateAcknowledge
}
func BridgeSuccessfulValueFieldBodyERABModificationConfirm(v *SuccessfulValue) **s39.ERABModificationConfirm {
	return &v.bodyERABModificationConfirm
}
func BridgeSuccessfulValueFieldBodyERABModifyResponse(v *SuccessfulValue) **s46.ERABModifyResponse {
	return &v.bodyERABModifyResponse
}
func BridgeSuccessfulValueFieldBodyERABReleaseResponse(v *SuccessfulValue) **s46.ERABReleaseResponse {
	return &v.bodyERABReleaseResponse
}
func BridgeSuccessfulValueFieldBodyERABSetupResponse(v *SuccessfulValue) **s46.ERABSetupResponse {
	return &v.bodyERABSetupResponse
}
func BridgeSuccessfulValueFieldBodyHandoverCancelAcknowledge(v *SuccessfulValue) **s25.HandoverCancelAcknowledge {
	return &v.bodyHandoverCancelAcknowledge
}
func BridgeSuccessfulValueFieldBodyHandoverCommand(v *SuccessfulValue) **s40.HandoverCommand {
	return &v.bodyHandoverCommand
}
func BridgeSuccessfulValueFieldBodyHandoverRequestAcknowledge(v *SuccessfulValue) **s39.HandoverRequestAcknowledge {
	return &v.bodyHandoverRequestAcknowledge
}
func BridgeSuccessfulValueFieldBodyInitialContextSetupResponse(v *SuccessfulValue) **s40.InitialContextSetupResponse {
	return &v.bodyInitialContextSetupResponse
}
func BridgeSuccessfulValueFieldBodyKillResponse(v *SuccessfulValue) **s33.KillResponse {
	return &v.bodyKillResponse
}
func BridgeSuccessfulValueFieldBodyMMEConfigurationUpdateAcknowledge(v *SuccessfulValue) **s25.MMEConfigurationUpdateAcknowledge {
	return &v.bodyMMEConfigurationUpdateAcknowledge
}
func BridgeSuccessfulValueFieldBodyPathSwitchRequestAcknowledge(v *SuccessfulValue) **s47.PathSwitchRequestAcknowledge {
	return &v.bodyPathSwitchRequestAcknowledge
}
func BridgeSuccessfulValueFieldBodyResetAcknowledge(v *SuccessfulValue) **s44.ResetAcknowledge {
	return &v.bodyResetAcknowledge
}
func BridgeSuccessfulValueFieldBodyS1RemovalResponse(v *SuccessfulValue) **s26.S1RemovalResponse {
	return &v.bodyS1RemovalResponse
}
func BridgeSuccessfulValueFieldBodyS1SetupResponse(v *SuccessfulValue) **s43.S1SetupResponse {
	return &v.bodyS1SetupResponse
}
func BridgeSuccessfulValueFieldBodyUEContextModificationConfirm(v *SuccessfulValue) **s36.UEContextModificationConfirm {
	return &v.bodyUEContextModificationConfirm
}
func BridgeSuccessfulValueFieldBodyUEContextModificationResponse(v *SuccessfulValue) **s36.UEContextModificationResponse {
	return &v.bodyUEContextModificationResponse
}
func BridgeSuccessfulValueFieldBodyUEContextReleaseComplete(v *SuccessfulValue) **s46.UEContextReleaseComplete {
	return &v.bodyUEContextReleaseComplete
}
func BridgeSuccessfulValueFieldBodyUEContextResumeResponse(v *SuccessfulValue) **s38.UEContextResumeResponse {
	return &v.bodyUEContextResumeResponse
}
func BridgeSuccessfulValueFieldBodyUEContextSuspendResponse(v *SuccessfulValue) **s36.UEContextSuspendResponse {
	return &v.bodyUEContextSuspendResponse
}
func BridgeSuccessfulValueFieldBodyUERadioCapabilityIDMappingResponse(v *SuccessfulValue) **s36.UERadioCapabilityIDMappingResponse {
	return &v.bodyUERadioCapabilityIDMappingResponse
}
func BridgeSuccessfulValueFieldBodyUERadioCapabilityMatchResponse(v *SuccessfulValue) **s37.UERadioCapabilityMatchResponse {
	return &v.bodyUERadioCapabilityMatchResponse
}
func BridgeSuccessfulValueFieldBodyWriteReplaceWarningResponse(v *SuccessfulValue) **WriteReplaceWarningResponse {
	return &v.bodyWriteReplaceWarningResponse
}
func BridgeSuccessfulValueFieldCode(v *SuccessfulValue) *s00.ProcedureCode     { return &v.code }
func BridgeSuccessfulValueFieldIsOpaque(v *SuccessfulValue) *bool              { return &v.isOpaque }
func BridgeSuccessfulValueFieldOpaque(v *SuccessfulValue) *aper.OpaqueOpenType { return &v.opaque }
func BridgeSuccessfulValueFieldReceived(v *SuccessfulValue) *aper.WireSpan     { return &v.received }
func BridgeSuccessfulValueFieldReplay(v *SuccessfulValue) *aper.Snapshot       { return &v.replay }
func BridgeSuccessfulValueMethodCaptureSemantics(v SuccessfulValue, a0 aper.SemanticCapture) SuccessfulValue {
	return v.captureSemantics(a0)
}
func BridgeSuccessfulValueMethodCompareSemantics(v SuccessfulValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeSuccessfulValueMethodEncode(v SuccessfulValue) ([]byte, error) { return v.encode() }
func BridgeSuccessfulValueMethodEncodeFresh(v SuccessfulValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEContextModificationConfirmSuccessfulBindingFieldCapture(v *UEContextModificationConfirmSuccessfulBinding) *func(s36.UEContextModificationConfirm, aper.DecodeState) (s36.UEContextModificationConfirm, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationConfirmSuccessfulBindingFieldCompare(v *UEContextModificationConfirmSuccessfulBinding) *func(s36.UEContextModificationConfirm, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationConfirmSuccessfulBindingFieldContext(v *UEContextModificationConfirmSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmSuccessfulBindingFieldDecode(v *UEContextModificationConfirmSuccessfulBinding) *func([]byte, aper.DecodeState) (s36.UEContextModificationConfirm, error) {
	return &v.decode
}
func BridgeUEContextModificationConfirmSuccessfulBindingFieldEncode(v *UEContextModificationConfirmSuccessfulBinding) *func(*s36.UEContextModificationConfirm, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationConfirmSuccessfulBindingFieldInfo(v *UEContextModificationConfirmSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextModificationConfirmSuccessfulBindingFieldInject(v *UEContextModificationConfirmSuccessfulBinding) *func(s36.UEContextModificationConfirm) SuccessfulValue {
	return &v.inject
}
func BridgeUEContextModificationConfirmSuccessfulBindingFieldValidate(v *UEContextModificationConfirmSuccessfulBinding) *func(*s36.UEContextModificationConfirm, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldCapture(v *UEContextModificationResponseSuccessfulBinding) *func(s36.UEContextModificationResponse, aper.DecodeState) (s36.UEContextModificationResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldCompare(v *UEContextModificationResponseSuccessfulBinding) *func(s36.UEContextModificationResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldContext(v *UEContextModificationResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldDecode(v *UEContextModificationResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s36.UEContextModificationResponse, error) {
	return &v.decode
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldEncode(v *UEContextModificationResponseSuccessfulBinding) *func(*s36.UEContextModificationResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldInfo(v *UEContextModificationResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldInject(v *UEContextModificationResponseSuccessfulBinding) *func(s36.UEContextModificationResponse) SuccessfulValue {
	return &v.inject
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldValidate(v *UEContextModificationResponseSuccessfulBinding) *func(*s36.UEContextModificationResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldCapture(v *UEContextReleaseCompleteSuccessfulBinding) *func(s46.UEContextReleaseComplete, aper.DecodeState) (s46.UEContextReleaseComplete, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldCompare(v *UEContextReleaseCompleteSuccessfulBinding) *func(s46.UEContextReleaseComplete, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldContext(v *UEContextReleaseCompleteSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldDecode(v *UEContextReleaseCompleteSuccessfulBinding) *func([]byte, aper.DecodeState) (s46.UEContextReleaseComplete, error) {
	return &v.decode
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldEncode(v *UEContextReleaseCompleteSuccessfulBinding) *func(*s46.UEContextReleaseComplete, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldInfo(v *UEContextReleaseCompleteSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldInject(v *UEContextReleaseCompleteSuccessfulBinding) *func(s46.UEContextReleaseComplete) SuccessfulValue {
	return &v.inject
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldValidate(v *UEContextReleaseCompleteSuccessfulBinding) *func(*s46.UEContextReleaseComplete, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldCapture(v *UEContextResumeResponseSuccessfulBinding) *func(s38.UEContextResumeResponse, aper.DecodeState) (s38.UEContextResumeResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldCompare(v *UEContextResumeResponseSuccessfulBinding) *func(s38.UEContextResumeResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldContext(v *UEContextResumeResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldDecode(v *UEContextResumeResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s38.UEContextResumeResponse, error) {
	return &v.decode
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldEncode(v *UEContextResumeResponseSuccessfulBinding) *func(*s38.UEContextResumeResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldInfo(v *UEContextResumeResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldInject(v *UEContextResumeResponseSuccessfulBinding) *func(s38.UEContextResumeResponse) SuccessfulValue {
	return &v.inject
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldValidate(v *UEContextResumeResponseSuccessfulBinding) *func(*s38.UEContextResumeResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldCapture(v *UEContextSuspendResponseSuccessfulBinding) *func(s36.UEContextSuspendResponse, aper.DecodeState) (s36.UEContextSuspendResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldCompare(v *UEContextSuspendResponseSuccessfulBinding) *func(s36.UEContextSuspendResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldContext(v *UEContextSuspendResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldDecode(v *UEContextSuspendResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s36.UEContextSuspendResponse, error) {
	return &v.decode
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldEncode(v *UEContextSuspendResponseSuccessfulBinding) *func(*s36.UEContextSuspendResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldInfo(v *UEContextSuspendResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldInject(v *UEContextSuspendResponseSuccessfulBinding) *func(s36.UEContextSuspendResponse) SuccessfulValue {
	return &v.inject
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldValidate(v *UEContextSuspendResponseSuccessfulBinding) *func(*s36.UEContextSuspendResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldCapture(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func(s36.UERadioCapabilityIDMappingResponse, aper.DecodeState) (s36.UERadioCapabilityIDMappingResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldCompare(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func(s36.UERadioCapabilityIDMappingResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldContext(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldDecode(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s36.UERadioCapabilityIDMappingResponse, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldEncode(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func(*s36.UERadioCapabilityIDMappingResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldInfo(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldInject(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func(s36.UERadioCapabilityIDMappingResponse) SuccessfulValue {
	return &v.inject
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldValidate(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func(*s36.UERadioCapabilityIDMappingResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldCapture(v *UERadioCapabilityMatchResponseSuccessfulBinding) *func(s37.UERadioCapabilityMatchResponse, aper.DecodeState) (s37.UERadioCapabilityMatchResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldCompare(v *UERadioCapabilityMatchResponseSuccessfulBinding) *func(s37.UERadioCapabilityMatchResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldContext(v *UERadioCapabilityMatchResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldDecode(v *UERadioCapabilityMatchResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s37.UERadioCapabilityMatchResponse, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldEncode(v *UERadioCapabilityMatchResponseSuccessfulBinding) *func(*s37.UERadioCapabilityMatchResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldInfo(v *UERadioCapabilityMatchResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldInject(v *UERadioCapabilityMatchResponseSuccessfulBinding) *func(s37.UERadioCapabilityMatchResponse) SuccessfulValue {
	return &v.inject
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldValidate(v *UERadioCapabilityMatchResponseSuccessfulBinding) *func(*s37.UERadioCapabilityMatchResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeWriteReplaceWarningRequestAPERValueFieldContext(v *WriteReplaceWarningRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningRequestAPERValueFieldReceived(v *WriteReplaceWarningRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWriteReplaceWarningRequestAPERValueFieldReplay(v *WriteReplaceWarningRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningRequestAPERValueFieldWithoutReplay(v *WriteReplaceWarningRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningRequestFieldExtCount(v *WriteReplaceWarningRequest) *int64 {
	return &v.extCount
}
func BridgeWriteReplaceWarningRequestFieldExtData(v *WriteReplaceWarningRequest) *[][]byte {
	return &v.extData
}
func BridgeWriteReplaceWarningRequestFieldExtOrigin(v *WriteReplaceWarningRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeWriteReplaceWarningRequestFieldExtPresent(v *WriteReplaceWarningRequest) *[]bool {
	return &v.extPresent
}
func BridgeWriteReplaceWarningRequestFieldExtWire(v *WriteReplaceWarningRequest) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeWriteReplaceWarningRequestFieldPerExtPadding(v *WriteReplaceWarningRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeWriteReplaceWarningRequestFieldPerPadding(v *WriteReplaceWarningRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeWriteReplaceWarningRequestFieldProtocolIEsIndef(v *WriteReplaceWarningRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgeWriteReplaceWarningRequestFieldReceived(v *WriteReplaceWarningRequest) *bool {
	return &v.received
}
func BridgeWriteReplaceWarningRequestFieldReceivedAbsolute(v *WriteReplaceWarningRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeWriteReplaceWarningRequestFieldReceivedBytes(v *WriteReplaceWarningRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeWriteReplaceWarningRequestFieldReceivedLocation(v *WriteReplaceWarningRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeWriteReplaceWarningRequestFieldReplay(v *WriteReplaceWarningRequest) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningRequestFieldStream(v *WriteReplaceWarningRequest) *aper.WireSpan {
	return &v.stream
}
func BridgeWriteReplaceWarningRequestFieldWithoutReplay(v *WriteReplaceWarningRequest) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningRequestMethodMarshalAPERBudget(v *WriteReplaceWarningRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWriteReplaceWarningRequestMethodMarshalAPERBudgetValue(v *WriteReplaceWarningRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeWriteReplaceWarningRequestMethodMarshalAPERChanged(v *WriteReplaceWarningRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWriteReplaceWarningRequestMethodMarshalAPERChangedValue(v *WriteReplaceWarningRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWriteReplaceWarningRequestMethodMarshalAPERLegacy(v *WriteReplaceWarningRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWriteReplaceWarningRequestMethodMarshalAPERNewValue(v *WriteReplaceWarningRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeWriteReplaceWarningRequestMethodMarshalAPERPlanned(v *WriteReplaceWarningRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeWriteReplaceWarningRequestMethodMarshalAPERTo(v *WriteReplaceWarningRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWriteReplaceWarningRequestMethodUnmarshalAPERFrom(v *WriteReplaceWarningRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWriteReplaceWarningRequestMethodUnmarshalAPERLegacy(v *WriteReplaceWarningRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWriteReplaceWarningRequestMethodUnmarshalAPERWithOptions(v *WriteReplaceWarningRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWriteReplaceWarningRequestValueCodecFieldCapture(v *WriteReplaceWarningRequestValueCodec) *func(WriteReplaceWarningRequest, aper.DecodeState) (WriteReplaceWarningRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningRequestValueCodecFieldCompare(v *WriteReplaceWarningRequestValueCodec) *func(WriteReplaceWarningRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningRequestValueCodecFieldContext(v *WriteReplaceWarningRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningRequestValueCodecFieldDecode(v *WriteReplaceWarningRequestValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningRequest, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningRequestValueCodecFieldEncode(v *WriteReplaceWarningRequestValueCodec) *func(WriteReplaceWarningRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningRequestValueCodecFieldPath(v *WriteReplaceWarningRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningRequestValueCodecMethodEncodeBudgetValue(v WriteReplaceWarningRequestValueCodec, a0 WriteReplaceWarningRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWriteReplaceWarningRequestValueCodecMethodEncodeChanged(v WriteReplaceWarningRequestValueCodec, a0 WriteReplaceWarningRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWriteReplaceWarningResponseAPERValueFieldContext(v *WriteReplaceWarningResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseAPERValueFieldReceived(v *WriteReplaceWarningResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWriteReplaceWarningResponseAPERValueFieldReplay(v *WriteReplaceWarningResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningResponseAPERValueFieldWithoutReplay(v *WriteReplaceWarningResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningResponseFieldExtCount(v *WriteReplaceWarningResponse) *int64 {
	return &v.extCount
}
func BridgeWriteReplaceWarningResponseFieldExtData(v *WriteReplaceWarningResponse) *[][]byte {
	return &v.extData
}
func BridgeWriteReplaceWarningResponseFieldExtOrigin(v *WriteReplaceWarningResponse) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeWriteReplaceWarningResponseFieldExtPresent(v *WriteReplaceWarningResponse) *[]bool {
	return &v.extPresent
}
func BridgeWriteReplaceWarningResponseFieldExtWire(v *WriteReplaceWarningResponse) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeWriteReplaceWarningResponseFieldPerExtPadding(v *WriteReplaceWarningResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeWriteReplaceWarningResponseFieldPerPadding(v *WriteReplaceWarningResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeWriteReplaceWarningResponseFieldProtocolIEsIndef(v *WriteReplaceWarningResponse) *bool {
	return &v.protocolIEsIndef
}
func BridgeWriteReplaceWarningResponseFieldReceived(v *WriteReplaceWarningResponse) *bool {
	return &v.received
}
func BridgeWriteReplaceWarningResponseFieldReceivedAbsolute(v *WriteReplaceWarningResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeWriteReplaceWarningResponseFieldReceivedBytes(v *WriteReplaceWarningResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeWriteReplaceWarningResponseFieldReceivedLocation(v *WriteReplaceWarningResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeWriteReplaceWarningResponseFieldReplay(v *WriteReplaceWarningResponse) *aper.Snapshot {
	return &v.replay
}
func BridgeWriteReplaceWarningResponseFieldStream(v *WriteReplaceWarningResponse) *aper.WireSpan {
	return &v.stream
}
func BridgeWriteReplaceWarningResponseFieldWithoutReplay(v *WriteReplaceWarningResponse) *bool {
	return &v.withoutReplay
}
func BridgeWriteReplaceWarningResponseMethodMarshalAPERBudget(v *WriteReplaceWarningResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWriteReplaceWarningResponseMethodMarshalAPERBudgetValue(v *WriteReplaceWarningResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeWriteReplaceWarningResponseMethodMarshalAPERChanged(v *WriteReplaceWarningResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWriteReplaceWarningResponseMethodMarshalAPERChangedValue(v *WriteReplaceWarningResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWriteReplaceWarningResponseMethodMarshalAPERLegacy(v *WriteReplaceWarningResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWriteReplaceWarningResponseMethodMarshalAPERNewValue(v *WriteReplaceWarningResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeWriteReplaceWarningResponseMethodMarshalAPERPlanned(v *WriteReplaceWarningResponse, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeWriteReplaceWarningResponseMethodMarshalAPERTo(v *WriteReplaceWarningResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWriteReplaceWarningResponseMethodUnmarshalAPERFrom(v *WriteReplaceWarningResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWriteReplaceWarningResponseMethodUnmarshalAPERLegacy(v *WriteReplaceWarningResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWriteReplaceWarningResponseMethodUnmarshalAPERWithOptions(v *WriteReplaceWarningResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWriteReplaceWarningResponseSuccessfulBindingFieldCapture(v *WriteReplaceWarningResponseSuccessfulBinding) *func(WriteReplaceWarningResponse, aper.DecodeState) (WriteReplaceWarningResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningResponseSuccessfulBindingFieldCompare(v *WriteReplaceWarningResponseSuccessfulBinding) *func(WriteReplaceWarningResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningResponseSuccessfulBindingFieldContext(v *WriteReplaceWarningResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseSuccessfulBindingFieldDecode(v *WriteReplaceWarningResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (WriteReplaceWarningResponse, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningResponseSuccessfulBindingFieldEncode(v *WriteReplaceWarningResponseSuccessfulBinding) *func(*WriteReplaceWarningResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningResponseSuccessfulBindingFieldInfo(v *WriteReplaceWarningResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeWriteReplaceWarningResponseSuccessfulBindingFieldInject(v *WriteReplaceWarningResponseSuccessfulBinding) *func(WriteReplaceWarningResponse) SuccessfulValue {
	return &v.inject
}
func BridgeWriteReplaceWarningResponseSuccessfulBindingFieldValidate(v *WriteReplaceWarningResponseSuccessfulBinding) *func(*WriteReplaceWarningResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeWriteReplaceWarningResponseValueCodecFieldCapture(v *WriteReplaceWarningResponseValueCodec) *func(WriteReplaceWarningResponse, aper.DecodeState) (WriteReplaceWarningResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeWriteReplaceWarningResponseValueCodecFieldCompare(v *WriteReplaceWarningResponseValueCodec) *func(WriteReplaceWarningResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWriteReplaceWarningResponseValueCodecFieldContext(v *WriteReplaceWarningResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWriteReplaceWarningResponseValueCodecFieldDecode(v *WriteReplaceWarningResponseValueCodec) *func([]byte, aper.DecodeState) (WriteReplaceWarningResponse, error) {
	return &v.decode
}
func BridgeWriteReplaceWarningResponseValueCodecFieldEncode(v *WriteReplaceWarningResponseValueCodec) *func(WriteReplaceWarningResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWriteReplaceWarningResponseValueCodecFieldPath(v *WriteReplaceWarningResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeWriteReplaceWarningResponseValueCodecMethodEncodeBudgetValue(v WriteReplaceWarningResponseValueCodec, a0 WriteReplaceWarningResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWriteReplaceWarningResponseValueCodecMethodEncodeChanged(v WriteReplaceWarningResponseValueCodec, a0 WriteReplaceWarningResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeX2TNLConfigurationInfoFieldENBX2TransportLayerAddressesIndef(v *X2TNLConfigurationInfo) *bool {
	return &v.eNBX2TransportLayerAddressesIndef
}
func BridgeX2TNLConfigurationInfoFieldExtCount(v *X2TNLConfigurationInfo) *int64   { return &v.extCount }
func BridgeX2TNLConfigurationInfoFieldExtData(v *X2TNLConfigurationInfo) *[][]byte { return &v.extData }
func BridgeX2TNLConfigurationInfoFieldExtOrigin(v *X2TNLConfigurationInfo) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeX2TNLConfigurationInfoFieldExtPresent(v *X2TNLConfigurationInfo) *[]bool {
	return &v.extPresent
}
func BridgeX2TNLConfigurationInfoFieldExtWire(v *X2TNLConfigurationInfo) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeX2TNLConfigurationInfoFieldIEExtensionsIndef(v *X2TNLConfigurationInfo) *bool {
	return &v.iEExtensionsIndef
}
func BridgeX2TNLConfigurationInfoFieldPerExtPadding(v *X2TNLConfigurationInfo) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeX2TNLConfigurationInfoFieldPerPadding(v *X2TNLConfigurationInfo) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeX2TNLConfigurationInfoFieldReceived(v *X2TNLConfigurationInfo) *bool { return &v.received }
func BridgeX2TNLConfigurationInfoFieldReceivedAbsolute(v *X2TNLConfigurationInfo) *bool {
	return &v.receivedAbsolute
}
func BridgeX2TNLConfigurationInfoFieldReceivedBytes(v *X2TNLConfigurationInfo) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeX2TNLConfigurationInfoFieldReceivedLocation(v *X2TNLConfigurationInfo) *aper.Location {
	return &v.receivedLocation
}
func BridgeX2TNLConfigurationInfoFieldReplay(v *X2TNLConfigurationInfo) *aper.Snapshot {
	return &v.replay
}
func BridgeX2TNLConfigurationInfoFieldStream(v *X2TNLConfigurationInfo) *aper.WireSpan {
	return &v.stream
}
func BridgeX2TNLConfigurationInfoFieldWithoutReplay(v *X2TNLConfigurationInfo) *bool {
	return &v.withoutReplay
}
func BridgeX2TNLConfigurationInfoMethodMarshalAPERBudget(v *X2TNLConfigurationInfo, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeX2TNLConfigurationInfoMethodMarshalAPERBudgetValue(v *X2TNLConfigurationInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeX2TNLConfigurationInfoMethodMarshalAPERChanged(v *X2TNLConfigurationInfo, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeX2TNLConfigurationInfoMethodMarshalAPERChangedValue(v *X2TNLConfigurationInfo, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeX2TNLConfigurationInfoMethodMarshalAPERLegacy(v *X2TNLConfigurationInfo) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeX2TNLConfigurationInfoMethodMarshalAPERNewValue(v *X2TNLConfigurationInfo, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeX2TNLConfigurationInfoMethodMarshalAPERPlanned(v *X2TNLConfigurationInfo, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeX2TNLConfigurationInfoMethodMarshalAPERTo(v *X2TNLConfigurationInfo, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeX2TNLConfigurationInfoMethodUnmarshalAPERFrom(v *X2TNLConfigurationInfo, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeX2TNLConfigurationInfoMethodUnmarshalAPERLegacy(v *X2TNLConfigurationInfo, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeX2TNLConfigurationInfoMethodUnmarshalAPERWithOptions(v *X2TNLConfigurationInfo, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *SONConfigurationTransferExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 152:
		if value, ok := v.AsX2TNLConfigurationInfo(); ok {
			return value, true
		}
	case 209:
		if value, ok := v.AsSynchronisationInformation(); ok {
			return value, true
		}
	case 356:
		if value, ok := v.AsRequestedTNLInfo(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *SuccessfulValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.code {
	case 0:
		if value, ok := v.AsHandoverCommand(); ok {
			return value, true
		}
	case 1:
		if value, ok := v.AsHandoverRequestAcknowledge(); ok {
			return value, true
		}
	case 3:
		if value, ok := v.AsPathSwitchRequestAcknowledge(); ok {
			return value, true
		}
	case 4:
		if value, ok := v.AsHandoverCancelAcknowledge(); ok {
			return value, true
		}
	case 5:
		if value, ok := v.AsERABSetupResponse(); ok {
			return value, true
		}
	case 6:
		if value, ok := v.AsERABModifyResponse(); ok {
			return value, true
		}
	case 7:
		if value, ok := v.AsERABReleaseResponse(); ok {
			return value, true
		}
	case 9:
		if value, ok := v.AsInitialContextSetupResponse(); ok {
			return value, true
		}
	case 14:
		if value, ok := v.AsResetAcknowledge(); ok {
			return value, true
		}
	case 17:
		if value, ok := v.AsS1SetupResponse(); ok {
			return value, true
		}
	case 21:
		if value, ok := v.AsUEContextModificationResponse(); ok {
			return value, true
		}
	case 23:
		if value, ok := v.AsUEContextReleaseComplete(); ok {
			return value, true
		}
	case 29:
		if value, ok := v.AsENBConfigurationUpdateAcknowledge(); ok {
			return value, true
		}
	case 30:
		if value, ok := v.AsMMEConfigurationUpdateAcknowledge(); ok {
			return value, true
		}
	case 36:
		if value, ok := v.AsWriteReplaceWarningResponse(); ok {
			return value, true
		}
	case 43:
		if value, ok := v.AsKillResponse(); ok {
			return value, true
		}
	case 48:
		if value, ok := v.AsUERadioCapabilityMatchResponse(); ok {
			return value, true
		}
	case 50:
		if value, ok := v.AsERABModificationConfirm(); ok {
			return value, true
		}
	case 53:
		if value, ok := v.AsUEContextModificationConfirm(); ok {
			return value, true
		}
	case 55:
		if value, ok := v.AsUEContextSuspendResponse(); ok {
			return value, true
		}
	case 56:
		if value, ok := v.AsUEContextResumeResponse(); ok {
			return value, true
		}
	case 63:
		if value, ok := v.AsUERadioCapabilityIDMappingResponse(); ok {
			return value, true
		}
	case 67:
		if value, ok := v.AsS1RemovalResponse(); ok {
			return value, true
		}
	}
	return nil, false
}
