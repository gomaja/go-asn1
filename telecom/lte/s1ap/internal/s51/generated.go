// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s51 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s51

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
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
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

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
func NewPathSwitchRequestAcknowledge(fields s47.PathSwitchRequestAcknowledgeIEContainer, options ...aper.BuildOption) (s48.PathSwitchRequestAcknowledge, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s48.PathSwitchRequestAcknowledge{}, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s47.PathSwitchRequestAcknowledgeIEField](bb, uint64(len(fields))); err != nil {
		return s48.PathSwitchRequestAcknowledge{}, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	v := s48.PathSwitchRequestAcknowledge{ProtocolIEs: make(s47.PathSwitchRequestAcknowledgeIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidatePathSwitchRequestAcknowledgeBudget(&v, budget)
	if err != nil {
		return s48.PathSwitchRequestAcknowledge{}, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s48.PathSwitchRequestAcknowledge{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "PathSwitchRequestAcknowledge")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s48.PathSwitchRequestAcknowledge{}, aper.OperationError(&s21.BuildError{Issues: issues}, "PathSwitchRequestAcknowledge")
	}
	if _, err := s48.BridgePathSwitchRequestAcknowledgeMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s48.PathSwitchRequestAcknowledge{}, aper.OperationError(fmt.Errorf("%s %w", "PathSwitchRequestAcknowledge.protocolIEs:", err), "PathSwitchRequestAcknowledge")
	}
	return v, aper.OperationError(nil, "PathSwitchRequestAcknowledge")
}
func NewERABSetupResponse(fields s46.ERABSetupResponseIEContainer, options ...aper.BuildOption) (s47.ERABSetupResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s47.ERABSetupResponse{}, aper.OperationError(err, "ERABSetupResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s46.ERABSetupResponseIEField](bb, uint64(len(fields))); err != nil {
		return s47.ERABSetupResponse{}, aper.OperationError(err, "ERABSetupResponse")
	}
	v := s47.ERABSetupResponse{ProtocolIEs: make(s46.ERABSetupResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABSetupResponseBudget(&v, budget)
	if err != nil {
		return s47.ERABSetupResponse{}, aper.OperationError(err, "ERABSetupResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s47.ERABSetupResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ERABSetupResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s47.ERABSetupResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ERABSetupResponse")
	}
	if _, err := s47.BridgeERABSetupResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s47.ERABSetupResponse{}, aper.OperationError(fmt.Errorf("%s %w", "ERABSetupResponse.protocolIEs:", err), "ERABSetupResponse")
	}
	return v, aper.OperationError(nil, "ERABSetupResponse")
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
func NewInitialContextSetupRequest(fields s49.InitialContextSetupRequestIEContainer, options ...aper.BuildOption) (s49.InitialContextSetupRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s49.InitialContextSetupRequest{}, aper.OperationError(err, "InitialContextSetupRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s49.InitialContextSetupRequestIEField](bb, uint64(len(fields))); err != nil {
		return s49.InitialContextSetupRequest{}, aper.OperationError(err, "InitialContextSetupRequest")
	}
	v := s49.InitialContextSetupRequest{ProtocolIEs: make(s49.InitialContextSetupRequestIEContainer, len(fields))}
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
func NewPaging(fields s50.PagingIEContainer, options ...aper.BuildOption) (s50.Paging, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s50.Paging{}, aper.OperationError(err, "Paging")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s50.PagingIEField](bb, uint64(len(fields))); err != nil {
		return s50.Paging{}, aper.OperationError(err, "Paging")
	}
	v := s50.Paging{ProtocolIEs: make(s50.PagingIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidatePagingBudget(&v, budget)
	if err != nil {
		return s50.Paging{}, aper.OperationError(err, "Paging")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s50.Paging{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Paging")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s50.Paging{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Paging")
	}
	if _, err := s50.BridgePagingMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s50.Paging{}, aper.OperationError(fmt.Errorf("%s %w", "Paging.protocolIEs:", err), "Paging")
	}
	return v, aper.OperationError(nil, "Paging")
}
func NewUplinkNASTransport(fields s32.UplinkNASTransportIEContainer, options ...aper.BuildOption) (s45.UplinkNASTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s45.UplinkNASTransport{}, aper.OperationError(err, "UplinkNASTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s32.UplinkNASTransportIEField](bb, uint64(len(fields))); err != nil {
		return s45.UplinkNASTransport{}, aper.OperationError(err, "UplinkNASTransport")
	}
	v := s45.UplinkNASTransport{ProtocolIEs: make(s32.UplinkNASTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUplinkNASTransportBudget(&v, budget)
	if err != nil {
		return s45.UplinkNASTransport{}, aper.OperationError(err, "UplinkNASTransport")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s45.UplinkNASTransport{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UplinkNASTransport")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s45.UplinkNASTransport{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UplinkNASTransport")
	}
	if _, err := s45.BridgeUplinkNASTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s45.UplinkNASTransport{}, aper.OperationError(fmt.Errorf("%s %w", "UplinkNASTransport.protocolIEs:", err), "UplinkNASTransport")
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
func NewResetAcknowledge(fields s45.ResetAcknowledgeIEContainer, options ...aper.BuildOption) (s45.ResetAcknowledge, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s45.ResetAcknowledge{}, aper.OperationError(err, "ResetAcknowledge")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s45.ResetAcknowledgeIEField](bb, uint64(len(fields))); err != nil {
		return s45.ResetAcknowledge{}, aper.OperationError(err, "ResetAcknowledge")
	}
	v := s45.ResetAcknowledge{ProtocolIEs: make(s45.ResetAcknowledgeIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateResetAcknowledgeBudget(&v, budget)
	if err != nil {
		return s45.ResetAcknowledge{}, aper.OperationError(err, "ResetAcknowledge")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s45.ResetAcknowledge{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ResetAcknowledge")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s45.ResetAcknowledge{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ResetAcknowledge")
	}
	if _, err := s45.BridgeResetAcknowledgeMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s45.ResetAcknowledge{}, aper.OperationError(fmt.Errorf("%s %w", "ResetAcknowledge.protocolIEs:", err), "ResetAcknowledge")
	}
	return v, aper.OperationError(nil, "ResetAcknowledge")
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
func NewUplinkS1cdma2000tunnelling(fields s21.UplinkS1cdma2000tunnellingIEContainer, options ...aper.BuildOption) (s45.UplinkS1cdma2000tunnelling, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s45.UplinkS1cdma2000tunnelling{}, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s21.UplinkS1cdma2000tunnellingIEField](bb, uint64(len(fields))); err != nil {
		return s45.UplinkS1cdma2000tunnelling{}, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	v := s45.UplinkS1cdma2000tunnelling{ProtocolIEs: make(s21.UplinkS1cdma2000tunnellingIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUplinkS1cdma2000tunnellingBudget(&v, budget)
	if err != nil {
		return s45.UplinkS1cdma2000tunnelling{}, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s45.UplinkS1cdma2000tunnelling{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UplinkS1cdma2000tunnelling")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s45.UplinkS1cdma2000tunnelling{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UplinkS1cdma2000tunnelling")
	}
	if _, err := s45.BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s45.UplinkS1cdma2000tunnelling{}, aper.OperationError(fmt.Errorf("%s %w", "UplinkS1cdma2000tunnelling.protocolIEs:", err), "UplinkS1cdma2000tunnelling")
	}
	return v, aper.OperationError(nil, "UplinkS1cdma2000tunnelling")
}
func NewUEContextModificationRequest(fields s47.UEContextModificationRequestIEContainer, options ...aper.BuildOption) (s48.UEContextModificationRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s48.UEContextModificationRequest{}, aper.OperationError(err, "UEContextModificationRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s47.UEContextModificationRequestIEField](bb, uint64(len(fields))); err != nil {
		return s48.UEContextModificationRequest{}, aper.OperationError(err, "UEContextModificationRequest")
	}
	v := s48.UEContextModificationRequest{ProtocolIEs: make(s47.UEContextModificationRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextModificationRequestBudget(&v, budget)
	if err != nil {
		return s48.UEContextModificationRequest{}, aper.OperationError(err, "UEContextModificationRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s48.UEContextModificationRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextModificationRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s48.UEContextModificationRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextModificationRequest")
	}
	if _, err := s48.BridgeUEContextModificationRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s48.UEContextModificationRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextModificationRequest.protocolIEs:", err), "UEContextModificationRequest")
	}
	return v, aper.OperationError(nil, "UEContextModificationRequest")
}
func NewUEContextModificationResponse(fields s23.UEContextModificationResponseIEContainer, options ...aper.BuildOption) (s37.UEContextModificationResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s37.UEContextModificationResponse{}, aper.OperationError(err, "UEContextModificationResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s23.UEContextModificationResponseIEField](bb, uint64(len(fields))); err != nil {
		return s37.UEContextModificationResponse{}, aper.OperationError(err, "UEContextModificationResponse")
	}
	v := s37.UEContextModificationResponse{ProtocolIEs: make(s23.UEContextModificationResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextModificationResponseBudget(&v, budget)
	if err != nil {
		return s37.UEContextModificationResponse{}, aper.OperationError(err, "UEContextModificationResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s37.UEContextModificationResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextModificationResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s37.UEContextModificationResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextModificationResponse")
	}
	if _, err := s37.BridgeUEContextModificationResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s37.UEContextModificationResponse{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextModificationResponse.protocolIEs:", err), "UEContextModificationResponse")
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
func NewUEContextReleaseComplete(fields s46.UEContextReleaseCompleteIEContainer, options ...aper.BuildOption) (s47.UEContextReleaseComplete, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s47.UEContextReleaseComplete{}, aper.OperationError(err, "UEContextReleaseComplete")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s46.UEContextReleaseCompleteIEField](bb, uint64(len(fields))); err != nil {
		return s47.UEContextReleaseComplete{}, aper.OperationError(err, "UEContextReleaseComplete")
	}
	v := s47.UEContextReleaseComplete{ProtocolIEs: make(s46.UEContextReleaseCompleteIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextReleaseCompleteBudget(&v, budget)
	if err != nil {
		return s47.UEContextReleaseComplete{}, aper.OperationError(err, "UEContextReleaseComplete")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s47.UEContextReleaseComplete{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextReleaseComplete")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s47.UEContextReleaseComplete{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextReleaseComplete")
	}
	if _, err := s47.BridgeUEContextReleaseCompleteMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s47.UEContextReleaseComplete{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextReleaseComplete.protocolIEs:", err), "UEContextReleaseComplete")
	}
	return v, aper.OperationError(nil, "UEContextReleaseComplete")
}
func NewTraceStart(fields s49.TraceStartIEContainer, options ...aper.BuildOption) (s49.TraceStart, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s49.TraceStart{}, aper.OperationError(err, "TraceStart")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s49.TraceStartIEField](bb, uint64(len(fields))); err != nil {
		return s49.TraceStart{}, aper.OperationError(err, "TraceStart")
	}
	v := s49.TraceStart{ProtocolIEs: make(s49.TraceStartIEContainer, len(fields))}
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
func NewWriteReplaceWarningResponse(fields s33.WriteReplaceWarningResponseIEContainer, options ...aper.BuildOption) (WriteReplaceWarningResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return WriteReplaceWarningResponse{}, aper.OperationError(err, "WriteReplaceWarningResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s33.WriteReplaceWarningResponseIEField](bb, uint64(len(fields))); err != nil {
		return WriteReplaceWarningResponse{}, aper.OperationError(err, "WriteReplaceWarningResponse")
	}
	v := WriteReplaceWarningResponse{ProtocolIEs: make(s33.WriteReplaceWarningResponseIEContainer, len(fields))}
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
func NewUplinkUEAssociatedLPPaTransport(fields s12.UplinkUEAssociatedLPPaTransportIEContainer, options ...aper.BuildOption) (s45.UplinkUEAssociatedLPPaTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s45.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UplinkUEAssociatedLPPaTransportIEField](bb, uint64(len(fields))); err != nil {
		return s45.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	v := s45.UplinkUEAssociatedLPPaTransport{ProtocolIEs: make(s12.UplinkUEAssociatedLPPaTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUplinkUEAssociatedLPPaTransportBudget(&v, budget)
	if err != nil {
		return s45.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s45.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UplinkUEAssociatedLPPaTransport")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s45.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UplinkUEAssociatedLPPaTransport")
	}
	if _, err := s45.BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s45.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(fmt.Errorf("%s %w", "UplinkUEAssociatedLPPaTransport.protocolIEs:", err), "UplinkUEAssociatedLPPaTransport")
	}
	return v, aper.OperationError(nil, "UplinkUEAssociatedLPPaTransport")
}
func NewUplinkNonUEAssociatedLPPaTransport(fields s12.UplinkNonUEAssociatedLPPaTransportIEContainer, options ...aper.BuildOption) (s45.UplinkNonUEAssociatedLPPaTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s45.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UplinkNonUEAssociatedLPPaTransportIEField](bb, uint64(len(fields))); err != nil {
		return s45.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	v := s45.UplinkNonUEAssociatedLPPaTransport{ProtocolIEs: make(s12.UplinkNonUEAssociatedLPPaTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUplinkNonUEAssociatedLPPaTransportBudget(&v, budget)
	if err != nil {
		return s45.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s45.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UplinkNonUEAssociatedLPPaTransport")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s45.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UplinkNonUEAssociatedLPPaTransport")
	}
	if _, err := s45.BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s45.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(fmt.Errorf("%s %w", "UplinkNonUEAssociatedLPPaTransport.protocolIEs:", err), "UplinkNonUEAssociatedLPPaTransport")
	}
	return v, aper.OperationError(nil, "UplinkNonUEAssociatedLPPaTransport")
}
func NewUERadioCapabilityMatchRequest(fields s12.UERadioCapabilityMatchRequestIEContainer, options ...aper.BuildOption) (s37.UERadioCapabilityMatchRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s37.UERadioCapabilityMatchRequest{}, aper.OperationError(err, "UERadioCapabilityMatchRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UERadioCapabilityMatchRequestIEField](bb, uint64(len(fields))); err != nil {
		return s37.UERadioCapabilityMatchRequest{}, aper.OperationError(err, "UERadioCapabilityMatchRequest")
	}
	v := s37.UERadioCapabilityMatchRequest{ProtocolIEs: make(s12.UERadioCapabilityMatchRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUERadioCapabilityMatchRequestBudget(&v, budget)
	if err != nil {
		return s37.UERadioCapabilityMatchRequest{}, aper.OperationError(err, "UERadioCapabilityMatchRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s37.UERadioCapabilityMatchRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UERadioCapabilityMatchRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s37.UERadioCapabilityMatchRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UERadioCapabilityMatchRequest")
	}
	if _, err := s37.BridgeUERadioCapabilityMatchRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s37.UERadioCapabilityMatchRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UERadioCapabilityMatchRequest.protocolIEs:", err), "UERadioCapabilityMatchRequest")
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
func NewERABModificationIndication(fields s45.ERABModificationIndicationIEContainer, options ...aper.BuildOption) (s46.ERABModificationIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.ERABModificationIndication{}, aper.OperationError(err, "ERABModificationIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s45.ERABModificationIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s46.ERABModificationIndication{}, aper.OperationError(err, "ERABModificationIndication")
	}
	v := s46.ERABModificationIndication{ProtocolIEs: make(s45.ERABModificationIndicationIEContainer, len(fields))}
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
func NewUEContextModificationIndication(fields s21.UEContextModificationIndicationIEContainer, options ...aper.BuildOption) (s37.UEContextModificationIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s37.UEContextModificationIndication{}, aper.OperationError(err, "UEContextModificationIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s21.UEContextModificationIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s37.UEContextModificationIndication{}, aper.OperationError(err, "UEContextModificationIndication")
	}
	v := s37.UEContextModificationIndication{ProtocolIEs: make(s21.UEContextModificationIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextModificationIndicationBudget(&v, budget)
	if err != nil {
		return s37.UEContextModificationIndication{}, aper.OperationError(err, "UEContextModificationIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s37.UEContextModificationIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextModificationIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s37.UEContextModificationIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextModificationIndication")
	}
	if _, err := s37.BridgeUEContextModificationIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s37.UEContextModificationIndication{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextModificationIndication.protocolIEs:", err), "UEContextModificationIndication")
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
func NewUEContextSuspendRequest(fields s46.UEContextSuspendRequestIEContainer, options ...aper.BuildOption) (s47.UEContextSuspendRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s47.UEContextSuspendRequest{}, aper.OperationError(err, "UEContextSuspendRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s46.UEContextSuspendRequestIEField](bb, uint64(len(fields))); err != nil {
		return s47.UEContextSuspendRequest{}, aper.OperationError(err, "UEContextSuspendRequest")
	}
	v := s47.UEContextSuspendRequest{ProtocolIEs: make(s46.UEContextSuspendRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextSuspendRequestBudget(&v, budget)
	if err != nil {
		return s47.UEContextSuspendRequest{}, aper.OperationError(err, "UEContextSuspendRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s47.UEContextSuspendRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextSuspendRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s47.UEContextSuspendRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextSuspendRequest")
	}
	if _, err := s47.BridgeUEContextSuspendRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s47.UEContextSuspendRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextSuspendRequest.protocolIEs:", err), "UEContextSuspendRequest")
	}
	return v, aper.OperationError(nil, "UEContextSuspendRequest")
}
func NewUEContextSuspendResponse(fields s29.UEContextSuspendResponseIEContainer, options ...aper.BuildOption) (s37.UEContextSuspendResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s37.UEContextSuspendResponse{}, aper.OperationError(err, "UEContextSuspendResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s29.UEContextSuspendResponseIEField](bb, uint64(len(fields))); err != nil {
		return s37.UEContextSuspendResponse{}, aper.OperationError(err, "UEContextSuspendResponse")
	}
	v := s37.UEContextSuspendResponse{ProtocolIEs: make(s29.UEContextSuspendResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextSuspendResponseBudget(&v, budget)
	if err != nil {
		return s37.UEContextSuspendResponse{}, aper.OperationError(err, "UEContextSuspendResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s37.UEContextSuspendResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextSuspendResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s37.UEContextSuspendResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextSuspendResponse")
	}
	if _, err := s37.BridgeUEContextSuspendResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s37.UEContextSuspendResponse{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextSuspendResponse.protocolIEs:", err), "UEContextSuspendResponse")
	}
	return v, aper.OperationError(nil, "UEContextSuspendResponse")
}
func NewUEContextResumeRequest(fields s39.UEContextResumeRequestIEContainer, options ...aper.BuildOption) (s39.UEContextResumeRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s39.UEContextResumeRequest{}, aper.OperationError(err, "UEContextResumeRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s39.UEContextResumeRequestIEField](bb, uint64(len(fields))); err != nil {
		return s39.UEContextResumeRequest{}, aper.OperationError(err, "UEContextResumeRequest")
	}
	v := s39.UEContextResumeRequest{ProtocolIEs: make(s39.UEContextResumeRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextResumeRequestBudget(&v, budget)
	if err != nil {
		return s39.UEContextResumeRequest{}, aper.OperationError(err, "UEContextResumeRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s39.UEContextResumeRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextResumeRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s39.UEContextResumeRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextResumeRequest")
	}
	if _, err := s39.BridgeUEContextResumeRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s39.UEContextResumeRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextResumeRequest.protocolIEs:", err), "UEContextResumeRequest")
	}
	return v, aper.OperationError(nil, "UEContextResumeRequest")
}
func NewUEContextResumeResponse(fields s39.UEContextResumeResponseIEContainer, options ...aper.BuildOption) (s39.UEContextResumeResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s39.UEContextResumeResponse{}, aper.OperationError(err, "UEContextResumeResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s39.UEContextResumeResponseIEField](bb, uint64(len(fields))); err != nil {
		return s39.UEContextResumeResponse{}, aper.OperationError(err, "UEContextResumeResponse")
	}
	v := s39.UEContextResumeResponse{ProtocolIEs: make(s39.UEContextResumeResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextResumeResponseBudget(&v, budget)
	if err != nil {
		return s39.UEContextResumeResponse{}, aper.OperationError(err, "UEContextResumeResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s39.UEContextResumeResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextResumeResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s39.UEContextResumeResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextResumeResponse")
	}
	if _, err := s39.BridgeUEContextResumeResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s39.UEContextResumeResponse{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextResumeResponse.protocolIEs:", err), "UEContextResumeResponse")
	}
	return v, aper.OperationError(nil, "UEContextResumeResponse")
}
func NewUEContextResumeFailure(fields s24.UEContextResumeFailureIEContainer, options ...aper.BuildOption) (s37.UEContextResumeFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s37.UEContextResumeFailure{}, aper.OperationError(err, "UEContextResumeFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s24.UEContextResumeFailureIEField](bb, uint64(len(fields))); err != nil {
		return s37.UEContextResumeFailure{}, aper.OperationError(err, "UEContextResumeFailure")
	}
	v := s37.UEContextResumeFailure{ProtocolIEs: make(s24.UEContextResumeFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextResumeFailureBudget(&v, budget)
	if err != nil {
		return s37.UEContextResumeFailure{}, aper.OperationError(err, "UEContextResumeFailure")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s37.UEContextResumeFailure{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEContextResumeFailure")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s37.UEContextResumeFailure{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEContextResumeFailure")
	}
	if _, err := s37.BridgeUEContextResumeFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s37.UEContextResumeFailure{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextResumeFailure.protocolIEs:", err), "UEContextResumeFailure")
	}
	return v, aper.OperationError(nil, "UEContextResumeFailure")
}
func NewUEInformationTransfer(fields s31.UEInformationTransferIEContainer, options ...aper.BuildOption) (s37.UEInformationTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s37.UEInformationTransfer{}, aper.OperationError(err, "UEInformationTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s31.UEInformationTransferIEField](bb, uint64(len(fields))); err != nil {
		return s37.UEInformationTransfer{}, aper.OperationError(err, "UEInformationTransfer")
	}
	v := s37.UEInformationTransfer{ProtocolIEs: make(s31.UEInformationTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEInformationTransferBudget(&v, budget)
	if err != nil {
		return s37.UEInformationTransfer{}, aper.OperationError(err, "UEInformationTransfer")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s37.UEInformationTransfer{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UEInformationTransfer")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s37.UEInformationTransfer{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UEInformationTransfer")
	}
	if _, err := s37.BridgeUEInformationTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s37.UEInformationTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "UEInformationTransfer.protocolIEs:", err), "UEInformationTransfer")
	}
	return v, aper.OperationError(nil, "UEInformationTransfer")
}
func NewENBCPRelocationIndication(fields s38.ENBCPRelocationIndicationIEContainer, options ...aper.BuildOption) (s38.ENBCPRelocationIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s38.ENBCPRelocationIndication{}, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s38.ENBCPRelocationIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s38.ENBCPRelocationIndication{}, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	v := s38.ENBCPRelocationIndication{ProtocolIEs: make(s38.ENBCPRelocationIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBCPRelocationIndicationBudget(&v, budget)
	if err != nil {
		return s38.ENBCPRelocationIndication{}, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s38.ENBCPRelocationIndication{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "ENBCPRelocationIndication")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s38.ENBCPRelocationIndication{}, aper.OperationError(&s21.BuildError{Issues: issues}, "ENBCPRelocationIndication")
	}
	if _, err := s38.BridgeENBCPRelocationIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s38.ENBCPRelocationIndication{}, aper.OperationError(fmt.Errorf("%s %w", "ENBCPRelocationIndication.protocolIEs:", err), "ENBCPRelocationIndication")
	}
	return v, aper.OperationError(nil, "ENBCPRelocationIndication")
}
func NewSecondaryRATDataUsageReport(fields s46.SecondaryRATDataUsageReportIEContainer, options ...aper.BuildOption) (s47.SecondaryRATDataUsageReport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s47.SecondaryRATDataUsageReport{}, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s46.SecondaryRATDataUsageReportIEField](bb, uint64(len(fields))); err != nil {
		return s47.SecondaryRATDataUsageReport{}, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	v := s47.SecondaryRATDataUsageReport{ProtocolIEs: make(s46.SecondaryRATDataUsageReportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateSecondaryRATDataUsageReportBudget(&v, budget)
	if err != nil {
		return s47.SecondaryRATDataUsageReport{}, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s47.SecondaryRATDataUsageReport{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "SecondaryRATDataUsageReport")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s47.SecondaryRATDataUsageReport{}, aper.OperationError(&s21.BuildError{Issues: issues}, "SecondaryRATDataUsageReport")
	}
	if _, err := s47.BridgeSecondaryRATDataUsageReportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s47.SecondaryRATDataUsageReport{}, aper.OperationError(fmt.Errorf("%s %w", "SecondaryRATDataUsageReport.protocolIEs:", err), "SecondaryRATDataUsageReport")
	}
	return v, aper.OperationError(nil, "SecondaryRATDataUsageReport")
}
func NewUERadioCapabilityIDMappingRequest(fields s12.UERadioCapabilityIDMappingRequestIEContainer, options ...aper.BuildOption) (s37.UERadioCapabilityIDMappingRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s37.UERadioCapabilityIDMappingRequest{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UERadioCapabilityIDMappingRequestIEField](bb, uint64(len(fields))); err != nil {
		return s37.UERadioCapabilityIDMappingRequest{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	v := s37.UERadioCapabilityIDMappingRequest{ProtocolIEs: make(s12.UERadioCapabilityIDMappingRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUERadioCapabilityIDMappingRequestBudget(&v, budget)
	if err != nil {
		return s37.UERadioCapabilityIDMappingRequest{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s37.UERadioCapabilityIDMappingRequest{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UERadioCapabilityIDMappingRequest")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s37.UERadioCapabilityIDMappingRequest{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UERadioCapabilityIDMappingRequest")
	}
	if _, err := s37.BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s37.UERadioCapabilityIDMappingRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UERadioCapabilityIDMappingRequest.protocolIEs:", err), "UERadioCapabilityIDMappingRequest")
	}
	return v, aper.OperationError(nil, "UERadioCapabilityIDMappingRequest")
}
func NewUERadioCapabilityIDMappingResponse(fields s24.UERadioCapabilityIDMappingResponseIEContainer, options ...aper.BuildOption) (s37.UERadioCapabilityIDMappingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s37.UERadioCapabilityIDMappingResponse{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s24.UERadioCapabilityIDMappingResponseIEField](bb, uint64(len(fields))); err != nil {
		return s37.UERadioCapabilityIDMappingResponse{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	v := s37.UERadioCapabilityIDMappingResponse{ProtocolIEs: make(s24.UERadioCapabilityIDMappingResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUERadioCapabilityIDMappingResponseBudget(&v, budget)
	if err != nil {
		return s37.UERadioCapabilityIDMappingResponse{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return s37.UERadioCapabilityIDMappingResponse{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "UERadioCapabilityIDMappingResponse")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s37.UERadioCapabilityIDMappingResponse{}, aper.OperationError(&s21.BuildError{Issues: issues}, "UERadioCapabilityIDMappingResponse")
	}
	if _, err := s37.BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s37.UERadioCapabilityIDMappingResponse{}, aper.OperationError(fmt.Errorf("%s %w", "UERadioCapabilityIDMappingResponse.protocolIEs:", err), "UERadioCapabilityIDMappingResponse")
	}
	return v, aper.OperationError(nil, "UERadioCapabilityIDMappingResponse")
}

// ENBConfigurationTransferIEContainer is ProtocolIE-Container {{ENBConfigurationTransferIEs}} of TS 36.413: a list of ENBConfigurationTransferIEField values.
type ENBConfigurationTransferIEContainer []ENBConfigurationTransferIEField

// ENBConfigurationTransferIEField is ProtocolIE-Field {{ENBConfigurationTransferIEs}} of TS 36.413: an information element field.
type ENBConfigurationTransferIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ENBConfigurationTransferIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationTransferIEField) WithoutReplay() ENBConfigurationTransferIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ENBConfigurationTransferIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ENBConfigurationTransferIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ENBConfigurationTransferIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBConfigurationTransferIEField{}
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
	var zero ENBConfigurationTransferIEValue

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

// HandoverCommandSuccessfulBinding is the concrete SuccessfulBinding[HandoverCommand].
type HandoverCommandSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s41.HandoverCommand, aper.DecodeState,

	) (s41.HandoverCommand, aper.Snapshot,

	)
	compare func(s41.HandoverCommand, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s41.HandoverCommand,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s41.HandoverCommand,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s41.HandoverCommand,

		error)
	inject func(s41.HandoverCommand,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b HandoverCommandSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCommandSuccessfulBinding) Codec() s41.HandoverCommandValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s41.HandoverCommandValueCodec{}
	}
	return func() s41.HandoverCommandValueCodec {
		sealed := s41.HandoverCommandValueCodec{}
		*s41.BridgeHandoverCommandValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s41.BridgeHandoverCommandValueCodecFieldDecode(&sealed) = b.decode
		*s41.BridgeHandoverCommandValueCodecFieldEncode(&sealed) = func(value s41.HandoverCommand,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s41.BridgeHandoverCommandValueCodecFieldCapture(&sealed) = b.capture
		*s41.BridgeHandoverCommandValueCodecFieldCompare(&sealed) = b.compare
		*s41.BridgeHandoverCommandValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverCommandSuccessfulBinding) Build(body s41.HandoverCommand,

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
	capture func(s48.PathSwitchRequestAcknowledge, aper.DecodeState,

	) (s48.PathSwitchRequestAcknowledge, aper.Snapshot,

	)
	compare func(s48.PathSwitchRequestAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s48.PathSwitchRequestAcknowledge,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s48.PathSwitchRequestAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s48.PathSwitchRequestAcknowledge,

		error)
	inject func(s48.PathSwitchRequestAcknowledge,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeSuccessfulBinding) Codec() s48.PathSwitchRequestAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s48.PathSwitchRequestAcknowledgeValueCodec{}
	}
	return func() s48.PathSwitchRequestAcknowledgeValueCodec {
		sealed := s48.PathSwitchRequestAcknowledgeValueCodec{}
		*s48.BridgePathSwitchRequestAcknowledgeValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s48.BridgePathSwitchRequestAcknowledgeValueCodecFieldDecode(&sealed) = b.decode
		*s48.BridgePathSwitchRequestAcknowledgeValueCodecFieldEncode(&sealed) = func(value s48.PathSwitchRequestAcknowledge,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s48.BridgePathSwitchRequestAcknowledgeValueCodecFieldCapture(&sealed) = b.capture
		*s48.BridgePathSwitchRequestAcknowledgeValueCodecFieldCompare(&sealed) = b.compare
		*s48.BridgePathSwitchRequestAcknowledgeValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b PathSwitchRequestAcknowledgeSuccessfulBinding) Build(body s48.PathSwitchRequestAcknowledge,

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
	capture func(s47.ERABSetupResponse, aper.DecodeState,

	) (s47.ERABSetupResponse, aper.Snapshot,

	)
	compare func(s47.ERABSetupResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s47.ERABSetupResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s47.ERABSetupResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s47.ERABSetupResponse,

		error)
	inject func(s47.ERABSetupResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ERABSetupResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupResponseSuccessfulBinding) Codec() s47.ERABSetupResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s47.ERABSetupResponseValueCodec{}
	}
	return func() s47.ERABSetupResponseValueCodec {
		sealed := s47.ERABSetupResponseValueCodec{}
		*s47.BridgeERABSetupResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s47.BridgeERABSetupResponseValueCodecFieldDecode(&sealed) = b.decode
		*s47.BridgeERABSetupResponseValueCodecFieldEncode(&sealed) = func(value s47.ERABSetupResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s47.BridgeERABSetupResponseValueCodecFieldCapture(&sealed) = b.capture
		*s47.BridgeERABSetupResponseValueCodecFieldCompare(&sealed) = b.compare
		*s47.BridgeERABSetupResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ERABSetupResponseSuccessfulBinding) Build(body s47.ERABSetupResponse,

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
	capture func(s45.ResetAcknowledge, aper.DecodeState,

	) (s45.ResetAcknowledge, aper.Snapshot,

	)
	compare func(s45.ResetAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s45.ResetAcknowledge,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s45.ResetAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s45.ResetAcknowledge,

		error)
	inject func(s45.ResetAcknowledge,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ResetAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ResetAcknowledgeSuccessfulBinding) Codec() s45.ResetAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s45.ResetAcknowledgeValueCodec{}
	}
	return func() s45.ResetAcknowledgeValueCodec {
		sealed := s45.ResetAcknowledgeValueCodec{}
		*s45.BridgeResetAcknowledgeValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s45.BridgeResetAcknowledgeValueCodecFieldDecode(&sealed) = b.decode
		*s45.BridgeResetAcknowledgeValueCodecFieldEncode(&sealed) = func(value s45.ResetAcknowledge,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s45.BridgeResetAcknowledgeValueCodecFieldCapture(&sealed) = b.capture
		*s45.BridgeResetAcknowledgeValueCodecFieldCompare(&sealed) = b.compare
		*s45.BridgeResetAcknowledgeValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ResetAcknowledgeSuccessfulBinding) Build(body s45.ResetAcknowledge,

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
	capture func(s44.S1SetupResponse, aper.DecodeState,

	) (s44.S1SetupResponse, aper.Snapshot,

	)
	compare func(s44.S1SetupResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s44.S1SetupResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s44.S1SetupResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s44.S1SetupResponse,

		error)
	inject func(s44.S1SetupResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b S1SetupResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupResponseSuccessfulBinding) Codec() s44.S1SetupResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s44.S1SetupResponseValueCodec{}
	}
	return func() s44.S1SetupResponseValueCodec {
		sealed := s44.S1SetupResponseValueCodec{}
		*s44.BridgeS1SetupResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s44.BridgeS1SetupResponseValueCodecFieldDecode(&sealed) = b.decode
		*s44.BridgeS1SetupResponseValueCodecFieldEncode(&sealed) = func(value s44.S1SetupResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s44.BridgeS1SetupResponseValueCodecFieldCapture(&sealed) = b.capture
		*s44.BridgeS1SetupResponseValueCodecFieldCompare(&sealed) = b.compare
		*s44.BridgeS1SetupResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1SetupResponseSuccessfulBinding) Build(body s44.S1SetupResponse,

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
	capture func(s37.UEContextModificationResponse, aper.DecodeState,

	) (s37.UEContextModificationResponse, aper.Snapshot,

	)
	compare func(s37.UEContextModificationResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s37.UEContextModificationResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s37.UEContextModificationResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s37.UEContextModificationResponse,

		error)
	inject func(s37.UEContextModificationResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationResponseSuccessfulBinding) Codec() s37.UEContextModificationResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s37.UEContextModificationResponseValueCodec{}
	}
	return func() s37.UEContextModificationResponseValueCodec {
		sealed := s37.UEContextModificationResponseValueCodec{}
		*s37.BridgeUEContextModificationResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s37.BridgeUEContextModificationResponseValueCodecFieldDecode(&sealed) = b.decode
		*s37.BridgeUEContextModificationResponseValueCodecFieldEncode(&sealed) = func(value s37.UEContextModificationResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s37.BridgeUEContextModificationResponseValueCodecFieldCapture(&sealed) = b.capture
		*s37.BridgeUEContextModificationResponseValueCodecFieldCompare(&sealed) = b.compare
		*s37.BridgeUEContextModificationResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextModificationResponseSuccessfulBinding) Build(body s37.UEContextModificationResponse,

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
	capture func(s47.UEContextReleaseComplete, aper.DecodeState,

	) (s47.UEContextReleaseComplete, aper.Snapshot,

	)
	compare func(s47.UEContextReleaseComplete, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s47.UEContextReleaseComplete,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s47.UEContextReleaseComplete,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s47.UEContextReleaseComplete,

		error)
	inject func(s47.UEContextReleaseComplete,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCompleteSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCompleteSuccessfulBinding) Codec() s47.UEContextReleaseCompleteValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s47.UEContextReleaseCompleteValueCodec{}
	}
	return func() s47.UEContextReleaseCompleteValueCodec {
		sealed := s47.UEContextReleaseCompleteValueCodec{}
		*s47.BridgeUEContextReleaseCompleteValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s47.BridgeUEContextReleaseCompleteValueCodecFieldDecode(&sealed) = b.decode
		*s47.BridgeUEContextReleaseCompleteValueCodecFieldEncode(&sealed) = func(value s47.UEContextReleaseComplete,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s47.BridgeUEContextReleaseCompleteValueCodecFieldCapture(&sealed) = b.capture
		*s47.BridgeUEContextReleaseCompleteValueCodecFieldCompare(&sealed) = b.compare
		*s47.BridgeUEContextReleaseCompleteValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextReleaseCompleteSuccessfulBinding) Build(body s47.UEContextReleaseComplete,

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
	capture func(s40.ERABModificationConfirm, aper.DecodeState,

	) (s40.ERABModificationConfirm, aper.Snapshot,

	)
	compare func(s40.ERABModificationConfirm, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s40.ERABModificationConfirm,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s40.ERABModificationConfirm,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s40.ERABModificationConfirm,

		error)
	inject func(s40.ERABModificationConfirm,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ERABModificationConfirmSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModificationConfirmSuccessfulBinding) Codec() s40.ERABModificationConfirmValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s40.ERABModificationConfirmValueCodec{}
	}
	return func() s40.ERABModificationConfirmValueCodec {
		sealed := s40.ERABModificationConfirmValueCodec{}
		*s40.BridgeERABModificationConfirmValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s40.BridgeERABModificationConfirmValueCodecFieldDecode(&sealed) = b.decode
		*s40.BridgeERABModificationConfirmValueCodecFieldEncode(&sealed) = func(value s40.ERABModificationConfirm,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s40.BridgeERABModificationConfirmValueCodecFieldCapture(&sealed) = b.capture
		*s40.BridgeERABModificationConfirmValueCodecFieldCompare(&sealed) = b.compare
		*s40.BridgeERABModificationConfirmValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ERABModificationConfirmSuccessfulBinding) Build(body s40.ERABModificationConfirm,

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
	capture func(s37.UEContextSuspendResponse, aper.DecodeState,

	) (s37.UEContextSuspendResponse, aper.Snapshot,

	)
	compare func(s37.UEContextSuspendResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s37.UEContextSuspendResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s37.UEContextSuspendResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s37.UEContextSuspendResponse,

		error)
	inject func(s37.UEContextSuspendResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendResponseSuccessfulBinding) Codec() s37.UEContextSuspendResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s37.UEContextSuspendResponseValueCodec{}
	}
	return func() s37.UEContextSuspendResponseValueCodec {
		sealed := s37.UEContextSuspendResponseValueCodec{}
		*s37.BridgeUEContextSuspendResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s37.BridgeUEContextSuspendResponseValueCodecFieldDecode(&sealed) = b.decode
		*s37.BridgeUEContextSuspendResponseValueCodecFieldEncode(&sealed) = func(value s37.UEContextSuspendResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s37.BridgeUEContextSuspendResponseValueCodecFieldCapture(&sealed) = b.capture
		*s37.BridgeUEContextSuspendResponseValueCodecFieldCompare(&sealed) = b.compare
		*s37.BridgeUEContextSuspendResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextSuspendResponseSuccessfulBinding) Build(body s37.UEContextSuspendResponse,

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
	capture func(s39.UEContextResumeResponse, aper.DecodeState,

	) (s39.UEContextResumeResponse, aper.Snapshot,

	)
	compare func(s39.UEContextResumeResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s39.UEContextResumeResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s39.UEContextResumeResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s39.UEContextResumeResponse,

		error)
	inject func(s39.UEContextResumeResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeResponseSuccessfulBinding) Codec() s39.UEContextResumeResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s39.UEContextResumeResponseValueCodec{}
	}
	return func() s39.UEContextResumeResponseValueCodec {
		sealed := s39.UEContextResumeResponseValueCodec{}
		*s39.BridgeUEContextResumeResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s39.BridgeUEContextResumeResponseValueCodecFieldDecode(&sealed) = b.decode
		*s39.BridgeUEContextResumeResponseValueCodecFieldEncode(&sealed) = func(value s39.UEContextResumeResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s39.BridgeUEContextResumeResponseValueCodecFieldCapture(&sealed) = b.capture
		*s39.BridgeUEContextResumeResponseValueCodecFieldCompare(&sealed) = b.compare
		*s39.BridgeUEContextResumeResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextResumeResponseSuccessfulBinding) Build(body s39.UEContextResumeResponse,

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
	capture func(s37.UERadioCapabilityIDMappingResponse, aper.DecodeState,

	) (s37.UERadioCapabilityIDMappingResponse, aper.Snapshot,

	)
	compare func(s37.UERadioCapabilityIDMappingResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s37.UERadioCapabilityIDMappingResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s37.UERadioCapabilityIDMappingResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s37.UERadioCapabilityIDMappingResponse,

		error)
	inject func(s37.UERadioCapabilityIDMappingResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityIDMappingResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityIDMappingResponseSuccessfulBinding) Codec() s37.UERadioCapabilityIDMappingResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s37.UERadioCapabilityIDMappingResponseValueCodec{}
	}
	return func() s37.UERadioCapabilityIDMappingResponseValueCodec {
		sealed := s37.UERadioCapabilityIDMappingResponseValueCodec{}
		*s37.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s37.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldDecode(&sealed) = b.decode
		*s37.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldEncode(&sealed) = func(value s37.UERadioCapabilityIDMappingResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s37.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldCapture(&sealed) = b.capture
		*s37.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldCompare(&sealed) = b.compare
		*s37.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UERadioCapabilityIDMappingResponseSuccessfulBinding) Build(body s37.UERadioCapabilityIDMappingResponse,

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
	capture func(s27.S1RemovalResponse, aper.DecodeState,

	) (s27.S1RemovalResponse, aper.Snapshot,

	)
	compare func(s27.S1RemovalResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s27.S1RemovalResponse,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s27.S1RemovalResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s27.S1RemovalResponse,

		error)
	inject func(s27.S1RemovalResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b S1RemovalResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1RemovalResponseSuccessfulBinding) Codec() s27.S1RemovalResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s27.S1RemovalResponseValueCodec{}
	}
	return func() s27.S1RemovalResponseValueCodec {
		sealed := s27.S1RemovalResponseValueCodec{}
		*s27.BridgeS1RemovalResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s27.BridgeS1RemovalResponseValueCodecFieldDecode(&sealed) = b.decode
		*s27.BridgeS1RemovalResponseValueCodecFieldEncode(&sealed) = func(value s27.S1RemovalResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s27.BridgeS1RemovalResponseValueCodecFieldCapture(&sealed) = b.capture
		*s27.BridgeS1RemovalResponseValueCodecFieldCompare(&sealed) = b.compare
		*s27.BridgeS1RemovalResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1RemovalResponseSuccessfulBinding) Build(body s27.S1RemovalResponse,

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
func BridgeSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionContainer(v *SONConfigurationTransferExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionContainer(v *SONConfigurationTransferExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
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
func BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEContainer(v *s33.WriteReplaceWarningResponseIEContainer, s *aper.SemanticCapture) {
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
func BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEContainer(v *s33.WriteReplaceWarningResponseIEContainer, s *aper.SemanticComparison) {
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
func BridgeX2TNLConfigurationInfoExtIEsValueCaptureS1APProtocolExtensionContainer(v *s39.X2TNLConfigurationInfoExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeX2TNLConfigurationInfoExtIEsValueCompareS1APProtocolExtensionContainer(v *s39.X2TNLConfigurationInfoExtIEsExtContainer, s *aper.SemanticComparison) {
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

// SONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBinding binds X2TNLConfigurationInfo to the SONConfigurationTransfer-ExtIEs object set of TS 36.413.
type SONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBinding struct {
	info   s00.ExtensionInfo
	codec  X2TNLConfigurationInfoValueCodec
	inject func(X2TNLConfigurationInfo,

	) SONConfigurationTransferExtIEsValue

	get func(*SONConfigurationTransferExtIEsValue,

	) (*X2TNLConfigurationInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBinding) Codec() X2TNLConfigurationInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBinding) New(value X2TNLConfigurationInfo,

) (SONConfigurationTransferExtIEsExtField, error) {
	if b.inject == nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SONConfigurationTransferExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBinding) Get(field *SONConfigurationTransferExtIEsExtField) (*X2TNLConfigurationInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// X2TNLConfigurationInfoValueCodec is the concrete ValueCodec[X2TNLConfigurationInfo].
type X2TNLConfigurationInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (X2TNLConfigurationInfo,

		error)
	encode func(X2TNLConfigurationInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(X2TNLConfigurationInfo, aper.DecodeState,

	) (X2TNLConfigurationInfo, aper.Snapshot,

	)
	compare func(X2TNLConfigurationInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c X2TNLConfigurationInfoValueCodec) New(value X2TNLConfigurationInfo,

) (X2TNLConfigurationInfoAPERValue, error) {
	if c.encode == nil {
		return X2TNLConfigurationInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return X2TNLConfigurationInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return X2TNLConfigurationInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return X2TNLConfigurationInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c X2TNLConfigurationInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (X2TNLConfigurationInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return X2TNLConfigurationInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return X2TNLConfigurationInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return X2TNLConfigurationInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return X2TNLConfigurationInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c X2TNLConfigurationInfoValueCodec) EncodeAPER(value X2TNLConfigurationInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c X2TNLConfigurationInfoValueCodec) encodeBudgetValue(value X2TNLConfigurationInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c X2TNLConfigurationInfoValueCodec) encodeChanged(value X2TNLConfigurationInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
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

// ENBConfigurationTransferENDCSONConfigurationTransferIEBinding binds ENDCSONConfigurationTransfer to the ENBConfigurationTransferIEs object set of TS 36.413.
type ENBConfigurationTransferENDCSONConfigurationTransferIEBinding struct {
	info   s00.FieldInfo
	codec  ENDCSONConfigurationTransferValueCodec
	inject func(ENDCSONConfigurationTransfer,

	) ENBConfigurationTransferIEValue

	get func(*ENBConfigurationTransferIEValue,

	) (*ENDCSONConfigurationTransfer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationTransferENDCSONConfigurationTransferIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationTransferENDCSONConfigurationTransferIEBinding) Codec() ENDCSONConfigurationTransferValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBConfigurationTransferENDCSONConfigurationTransferIEBinding) New(value ENDCSONConfigurationTransfer,

) (ENBConfigurationTransferIEField, error) {
	if b.inject == nil {
		return ENBConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ENBConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationTransferENDCSONConfigurationTransferIEBinding) Get(field *ENBConfigurationTransferIEField) (*ENDCSONConfigurationTransfer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ENDCSONConfigurationTransferValueCodec is the concrete ValueCodec[ENDCSONConfigurationTransfer].
type ENDCSONConfigurationTransferValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENDCSONConfigurationTransfer,

		error)
	encode func(ENDCSONConfigurationTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENDCSONConfigurationTransfer, aper.DecodeState,

	) (ENDCSONConfigurationTransfer, aper.Snapshot,

	)
	compare func(ENDCSONConfigurationTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENDCSONConfigurationTransferValueCodec) New(value ENDCSONConfigurationTransfer,

) (ENDCSONConfigurationTransferAPERValue, error) {
	if c.encode == nil {
		return ENDCSONConfigurationTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCSONConfigurationTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCSONConfigurationTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENDCSONConfigurationTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENDCSONConfigurationTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCSONConfigurationTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENDCSONConfigurationTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENDCSONConfigurationTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENDCSONConfigurationTransferAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENDCSONConfigurationTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENDCSONConfigurationTransferValueCodec) EncodeAPER(value ENDCSONConfigurationTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENDCSONConfigurationTransferValueCodec) encodeBudgetValue(value ENDCSONConfigurationTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENDCSONConfigurationTransferValueCodec) encodeChanged(value ENDCSONConfigurationTransfer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationTransferIntersystemSONConfigurationTransferIEBinding binds IntersystemSONConfigurationTransfer to the ENBConfigurationTransferIEs object set of TS 36.413.
type ENBConfigurationTransferIntersystemSONConfigurationTransferIEBinding struct {
	info   s00.FieldInfo
	codec  s01.IntersystemSONConfigurationTransferValueCodec
	inject func(s00.IntersystemSONConfigurationTransfer,

	) ENBConfigurationTransferIEValue

	get func(*ENBConfigurationTransferIEValue,

	) (*s00.IntersystemSONConfigurationTransfer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationTransferIntersystemSONConfigurationTransferIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationTransferIntersystemSONConfigurationTransferIEBinding) Codec() s01.IntersystemSONConfigurationTransferValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b ENBConfigurationTransferIntersystemSONConfigurationTransferIEBinding) New(value s00.IntersystemSONConfigurationTransfer,

) (ENBConfigurationTransferIEField, error) {
	if b.inject == nil {
		return ENBConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeIntersystemSONConfigurationTransferValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ENBConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ENBConfigurationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ENBConfigurationTransferIntersystemSONConfigurationTransferIEBinding) Get(field *ENBConfigurationTransferIEField) (*s00.IntersystemSONConfigurationTransfer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// SONInformationValueCodec is the concrete ValueCodec[SONInformation].
type SONInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformation,

		error)
	encode func(SONInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformation, aper.DecodeState,

	) (SONInformation, aper.Snapshot,

	)
	compare func(SONInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationValueCodec) New(value SONInformation,

) (SONInformationAPERValue, error) {
	if c.encode == nil {
		return SONInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationValueCodec) EncodeAPER(value SONInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SONInformationValueCodec) encodeBudgetValue(value SONInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationValueCodec) encodeChanged(value SONInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationReplyValueCodec is the concrete ValueCodec[SONInformationReply].
type SONInformationReplyValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONInformationReply,

		error)
	encode func(SONInformationReply,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONInformationReply, aper.DecodeState,

	) (SONInformationReply, aper.Snapshot,

	)
	compare func(SONInformationReply, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationReplyValueCodec) New(value SONInformationReply,

) (SONInformationReplyAPERValue, error) {
	if c.encode == nil {
		return SONInformationReplyAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationReplyAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationReplyAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationReplyAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationReplyValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationReplyAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationReplyAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationReplyAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationReplyAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationReplyAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationReplyValueCodec) EncodeAPER(value SONInformationReplyAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SONInformationReplyValueCodec) encodeBudgetValue(value SONInformationReply,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationReplyValueCodec) encodeChanged(value SONInformationReply,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s27.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
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
func BridgeWriteReplaceWarningResponseIEValueValidateS1APIEContainer(fields s33.WriteReplaceWarningResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s33.BridgeWriteReplaceWarningResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s33.BridgeWriteReplaceWarningResponseIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s33.BridgeWriteReplaceWarningResponseIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s27.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
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
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s33.WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec {
		sealed := s33.WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec{}
		*s33.BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.WriteReplaceWarningRequestIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s33.WriteReplaceWarningRequestIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s33.WriteReplaceWarningRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s33.BridgeWriteReplaceWarningRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
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
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningRequestIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "WriteReplaceWarningRequestIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningRequestIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s33.WriteReplaceWarningRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldEncode(&codec))(s33.WriteReplaceWarningRequestIEContainer(value), fresh, budget)
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s33.WriteReplaceWarningRequestIEValueERABIEContainerList, options aper.DecodeState) (s33.WriteReplaceWarningRequestIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s33.WriteReplaceWarningRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
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
func WriteReplaceWarningResponseIEValueERABIEContainerListCodec(table s00.WriteReplaceWarningResponseIEValueIETable) s33.WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec {
	codec := WriteReplaceWarningResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s33.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s33.WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s33.WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec {
		sealed := s33.WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec{}
		*s33.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.WriteReplaceWarningResponseIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s33.WriteReplaceWarningResponseIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s33.WriteReplaceWarningResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s33.BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
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
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningResponseIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "WriteReplaceWarningResponseIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningResponseIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s33.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s33.WriteReplaceWarningResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s33.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldEncode(&codec))(s33.WriteReplaceWarningResponseIEContainer(value), fresh, budget)
		}
		*s33.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s33.WriteReplaceWarningResponseIEValueERABIEContainerList, options aper.DecodeState) (s33.WriteReplaceWarningResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s33.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s33.WriteReplaceWarningResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SONConfigurationTransferExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{SONConfigurationTransfer-ExtIEs}} codec of TS 36.413.
func SONConfigurationTransferExtIEsValueExtensionFieldTableCodec(table s00.SONConfigurationTransferExtIEsValueExtensionTable) SONConfigurationTransferExtIEsExtFieldValueCodec {
	if !*s00.BridgeSONConfigurationTransferExtIEsValueExtensionTableFieldBound(&table) {
		return SONConfigurationTransferExtIEsExtFieldValueCodec{}
	}
	return SONConfigurationTransferExtIEsExtFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (SONConfigurationTransferExtIEsExtField, error) {
		var field SONConfigurationTransferExtIEsExtField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "SONConfigurationTransferExtIEsExtField")
		}
		if _, err := aper.CaptureFinalBits(bb, "SONConfigurationTransferExtIEsExtField"); err != nil {
			return field, runtime.WrapDecodePath(err, "SONConfigurationTransferExtIEsExtField")
		}
		return field, nil
	}, encode: func(field SONConfigurationTransferExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v SONConfigurationTransferExtIEsExtField, options aper.DecodeState) (SONConfigurationTransferExtIEsExtField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v SONConfigurationTransferExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
		s.End(f,

			root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// X2TNLConfigurationInfoExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{X2TNLConfigurationInfo-ExtIEs}} codec of TS 36.413.
func X2TNLConfigurationInfoExtIEsValueExtensionFieldTableCodec(table s00.X2TNLConfigurationInfoExtIEsValueExtensionTable) s39.X2TNLConfigurationInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeX2TNLConfigurationInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s39.X2TNLConfigurationInfoExtIEsExtFieldValueCodec{}
	}
	return func() s39.X2TNLConfigurationInfoExtIEsExtFieldValueCodec {
		sealed := s39.X2TNLConfigurationInfoExtIEsExtFieldValueCodec{}
		*s39.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s39.X2TNLConfigurationInfoExtIEsExtField, error) {
			var field s39.X2TNLConfigurationInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s39.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "X2TNLConfigurationInfoExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "X2TNLConfigurationInfoExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "X2TNLConfigurationInfoExtIEsExtField")
			}
			return field, nil
		}
		*s39.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s39.X2TNLConfigurationInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s39.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s39.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s39.X2TNLConfigurationInfoExtIEsExtField, options aper.DecodeState) (s39.X2TNLConfigurationInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeX2TNLConfigurationInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s39.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s39.X2TNLConfigurationInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeX2TNLConfigurationInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s39.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// X2TNLConfigurationInfoExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{X2TNLConfigurationInfo-ExtIEs}} codec of TS 36.413.
func X2TNLConfigurationInfoExtIEsValueExtensionTableCodec(table s00.X2TNLConfigurationInfoExtIEsValueExtensionTable, bounds aper.ListBounds) s39.X2TNLConfigurationInfoExtIEsExtContainerValueCodec {
	if !*s00.BridgeX2TNLConfigurationInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s39.X2TNLConfigurationInfoExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s39.X2TNLConfigurationInfoExtIEsExtContainerValueCodec {
		sealed := s39.X2TNLConfigurationInfoExtIEsExtContainerValueCodec{}
		*s39.BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s39.X2TNLConfigurationInfoExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s39.X2TNLConfigurationInfoExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s39.X2TNLConfigurationInfoExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s39.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
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
				return nil, runtime.WrapDecodePath(err, "X2TNLConfigurationInfoExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "X2TNLConfigurationInfoExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "X2TNLConfigurationInfoExtIEsExtContainer")
			}
			return fields, nil
		}
		*s39.BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s39.X2TNLConfigurationInfoExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s39.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s39.BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s39.X2TNLConfigurationInfoExtIEsExtContainer, options aper.DecodeState) (s39.X2TNLConfigurationInfoExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeX2TNLConfigurationInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s39.BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s39.X2TNLConfigurationInfoExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeX2TNLConfigurationInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s39.BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
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
				return field, runtime.WrapDecodePath(err, "WriteReplaceWarningRequestIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "WriteReplaceWarningRequestIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "WriteReplaceWarningRequestIEField")
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
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
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
func WriteReplaceWarningResponseIEValueIEFieldTableCodec(table s00.WriteReplaceWarningResponseIEValueIETable) s33.WriteReplaceWarningResponseIEFieldValueCodec {
	if !*s00.BridgeWriteReplaceWarningResponseIEValueIETableFieldBound(&table) {
		return s33.WriteReplaceWarningResponseIEFieldValueCodec{}
	}
	return func() s33.WriteReplaceWarningResponseIEFieldValueCodec {
		sealed := s33.WriteReplaceWarningResponseIEFieldValueCodec{}
		*s33.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.WriteReplaceWarningResponseIEField, error) {
			var field s33.WriteReplaceWarningResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s33.BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "WriteReplaceWarningResponseIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "WriteReplaceWarningResponseIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "WriteReplaceWarningResponseIEField")
			}
			return field, nil
		}
		*s33.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s33.WriteReplaceWarningResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s33.BridgeWriteReplaceWarningResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s33.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s33.WriteReplaceWarningResponseIEField, options aper.DecodeState) (s33.WriteReplaceWarningResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s33.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s33.WriteReplaceWarningResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s33.BridgeWriteReplaceWarningRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
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
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningRequestIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "WriteReplaceWarningRequestIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningRequestIEContainer")
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
			s.End(f, &root,

				false)
			return v, root
		}
		*s33.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldCompare(&sealed) = func(v s33.WriteReplaceWarningRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
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
func WriteReplaceWarningResponseIEValueIETableCodec(table s00.WriteReplaceWarningResponseIEValueIETable, bounds aper.ListBounds) s33.WriteReplaceWarningResponseIEContainerValueCodec {
	if !*s00.BridgeWriteReplaceWarningResponseIEValueIETableFieldBound(&table) {
		return s33.WriteReplaceWarningResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s33.WriteReplaceWarningResponseIEContainerValueCodec {
		sealed := s33.WriteReplaceWarningResponseIEContainerValueCodec{}
		*s33.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.WriteReplaceWarningResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s33.WriteReplaceWarningResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s33.WriteReplaceWarningResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s33.BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
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
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningResponseIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "WriteReplaceWarningResponseIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningResponseIEContainer")
			}
			return fields, nil
		}
		*s33.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s33.WriteReplaceWarningResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s33.BridgeWriteReplaceWarningResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s33.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s33.WriteReplaceWarningResponseIEContainer, options aper.DecodeState) (s33.WriteReplaceWarningResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s33.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s33.WriteReplaceWarningResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec{}
		*s33.BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s33.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s33.WriteReplaceWarningRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s33.BridgeWriteReplaceWarningRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
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
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
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
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
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
func WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListCodec(table s00.WriteReplaceWarningResponseIEValueIETable) s33.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := WriteReplaceWarningResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s33.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s33.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s33.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s33.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s33.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s33.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s33.WriteReplaceWarningResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s33.BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
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
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s33.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s33.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s33.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldEncode(&codec))(s33.WriteReplaceWarningResponseIEContainer(value), fresh, budget)
		}
		*s33.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s33.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s33.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s33.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s33.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s33.WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec {
		sealed := s33.WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec{}
		*s33.BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.WriteReplaceWarningRequestIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s33.WriteReplaceWarningRequestIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s33.WriteReplaceWarningRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s33.BridgeWriteReplaceWarningRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
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
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningRequestIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "WriteReplaceWarningRequestIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningRequestIEValueProtocolIEContainerList")
			}
			return fields, nil
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
			s.
				End(f, &root, false)
			return v, root
		}
		*s33.BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s33.WriteReplaceWarningRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
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
func WriteReplaceWarningResponseIEValueProtocolIEContainerListCodec(table s00.WriteReplaceWarningResponseIEValueIETable, bounds aper.ListBounds) s33.WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec {
	codec := WriteReplaceWarningResponseIEValueIETableCodec(table, bounds)
	if *s33.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s33.WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s33.WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s33.WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec{}
		*s33.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s33.WriteReplaceWarningResponseIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s33.WriteReplaceWarningResponseIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s33.WriteReplaceWarningResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s33.BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
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
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningResponseIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "WriteReplaceWarningResponseIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "WriteReplaceWarningResponseIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s33.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s33.WriteReplaceWarningResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s33.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldEncode(&codec))(s33.WriteReplaceWarningResponseIEContainer(value), fresh, budget)
		}
		*s33.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s33.WriteReplaceWarningResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s33.WriteReplaceWarningResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s33.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s33.WriteReplaceWarningResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s33.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func BridgeSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionField(v *SONConfigurationTransferExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionField(v *SONConfigurationTransferExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
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
	captureSemantics(aper.SemanticCapture) s33.WriteReplaceWarningResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s33.WriteReplaceWarningResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEField(v *s33.WriteReplaceWarningResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s33.BridgeWriteReplaceWarningResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s33.BridgeWriteReplaceWarningResponseIEFieldFieldReplay(v), *s33.BridgeWriteReplaceWarningResponseIEFieldFieldWithoutReplay(v))
}
func BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEField(v *s33.WriteReplaceWarningResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s33.BridgeWriteReplaceWarningResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s33.BridgeWriteReplaceWarningResponseIEFieldFieldReplay(v), *s33.BridgeWriteReplaceWarningResponseIEFieldFieldWithoutReplay(v))
}
func BridgeX2TNLConfigurationInfoExtIEsValueCaptureS1APProtocolExtensionField(v *s39.X2TNLConfigurationInfoExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s39.BridgeX2TNLConfigurationInfoExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s39.BridgeX2TNLConfigurationInfoExtIEsExtFieldFieldReplay(v), *s39.BridgeX2TNLConfigurationInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeX2TNLConfigurationInfoExtIEsValueCompareS1APProtocolExtensionField(v *s39.X2TNLConfigurationInfoExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s39.BridgeX2TNLConfigurationInfoExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s39.BridgeX2TNLConfigurationInfoExtIEsExtFieldFieldReplay(v), *s39.BridgeX2TNLConfigurationInfoExtIEsExtFieldFieldWithoutReplay(v))
}

// X2TNLConfigurationInfoAPERValue is the concrete APERValue[X2TNLConfigurationInfo].
type X2TNLConfigurationInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   X2TNLConfigurationInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v X2TNLConfigurationInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v X2TNLConfigurationInfoAPERValue) WithoutReplay() X2TNLConfigurationInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCSONConfigurationTransferAPERValue is the concrete APERValue[ENDCSONConfigurationTransfer].
type ENDCSONConfigurationTransferAPERValue struct {
	context s00.BridgeCodecContext
	Value   ENDCSONConfigurationTransfer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENDCSONConfigurationTransferAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENDCSONConfigurationTransferAPERValue) WithoutReplay() ENDCSONConfigurationTransferAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationAPERValue is the concrete APERValue[SONInformation].
type SONInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   SONInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationAPERValue) WithoutReplay() SONInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationReplyAPERValue is the concrete APERValue[SONInformationReply].
type SONInformationReplyAPERValue struct {
	context s00.BridgeCodecContext
	Value   SONInformationReply

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationReplyAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationReplyAPERValue) WithoutReplay() SONInformationReplyAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
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

// ENBConfigurationTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ENBConfigurationTransferIEValueERABIEContainerList].
type ENBConfigurationTransferIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationTransferIEValueERABIEContainerList, error)
	encode  func(ENBConfigurationTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationTransferIEValueERABIEContainerList, aper.DecodeState) (ENBConfigurationTransferIEValueERABIEContainerList, aper.Snapshot)
	compare func(ENBConfigurationTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationTransferIEValueERABIEContainerListValueCodec) New(value ENBConfigurationTransferIEValueERABIEContainerList) (ENBConfigurationTransferIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationTransferIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationTransferIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationTransferIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationTransferIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationTransferIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationTransferIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationTransferIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationTransferIEValueERABIEContainerListValueCodec) EncodeAPER(value ENBConfigurationTransferIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBConfigurationTransferIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ENBConfigurationTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationTransferIEValueERABIEContainerListValueCodec) encodeChanged(value ENBConfigurationTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationTransferIEValueERABIEContainerList is E-RAB-IE-ContainerList {{ENBConfigurationTransferIEs}} of TS 36.413: a list of information element fields.
type ENBConfigurationTransferIEValueERABIEContainerList []ENBConfigurationTransferIEValueProtocolIESingleContainer

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
func BridgeWriteReplaceWarningResponseIEValueCaptureS1APERABIEContainerList(v *s33.WriteReplaceWarningResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
func BridgeWriteReplaceWarningResponseIEValueCompareS1APERABIEContainerList(v *s33.WriteReplaceWarningResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
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

// ENBConfigurationTransferIEFieldValueCodec is the concrete ValueCodec[ENBConfigurationTransferIEField].
type ENBConfigurationTransferIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationTransferIEField, error)
	encode  func(ENBConfigurationTransferIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationTransferIEField, aper.DecodeState) (ENBConfigurationTransferIEField, aper.Snapshot)
	compare func(ENBConfigurationTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationTransferIEFieldValueCodec) New(value ENBConfigurationTransferIEField) (ENBConfigurationTransferIEFieldAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationTransferIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationTransferIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationTransferIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationTransferIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationTransferIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationTransferIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationTransferIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationTransferIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationTransferIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationTransferIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationTransferIEFieldValueCodec) EncodeAPER(value ENBConfigurationTransferIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBConfigurationTransferIEFieldValueCodec) encodeBudgetValue(value ENBConfigurationTransferIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationTransferIEFieldValueCodec) encodeChanged(value ENBConfigurationTransferIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationTransferIEContainerValueCodec is the concrete ValueCodec[ENBConfigurationTransferIEContainer].
type ENBConfigurationTransferIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationTransferIEContainer, error)
	encode  func(ENBConfigurationTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationTransferIEContainer, aper.DecodeState) (ENBConfigurationTransferIEContainer, aper.Snapshot)
	compare func(ENBConfigurationTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationTransferIEContainerValueCodec) New(value ENBConfigurationTransferIEContainer) (ENBConfigurationTransferIEContainerAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationTransferIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationTransferIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationTransferIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationTransferIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationTransferIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationTransferIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationTransferIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationTransferIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationTransferIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationTransferIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationTransferIEContainerValueCodec) EncodeAPER(value ENBConfigurationTransferIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBConfigurationTransferIEContainerValueCodec) encodeBudgetValue(value ENBConfigurationTransferIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationTransferIEContainerValueCodec) encodeChanged(value ENBConfigurationTransferIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ENBConfigurationTransferIEValueProtocolErrorIEContainerList].
type ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationTransferIEValueProtocolErrorIEContainerList, error)
	encode  func(ENBConfigurationTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBConfigurationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ENBConfigurationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) New(value ENBConfigurationTransferIEValueProtocolErrorIEContainerList) (ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ENBConfigurationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ENBConfigurationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationTransferIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{ENBConfigurationTransferIEs}} of TS 36.413: a list of information element fields.
type ENBConfigurationTransferIEValueProtocolErrorIEContainerList []ENBConfigurationTransferIEValueProtocolIESingleContainer

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
func BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s33.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
func BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s33.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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

// ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ENBConfigurationTransferIEValueProtocolIEContainerList].
type ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ENBConfigurationTransferIEValueProtocolIEContainerList, error)
	encode  func(ENBConfigurationTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ENBConfigurationTransferIEValueProtocolIEContainerList, aper.DecodeState) (ENBConfigurationTransferIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ENBConfigurationTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec) New(value ENBConfigurationTransferIEValueProtocolIEContainerList) (ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ENBConfigurationTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec) encodeChanged(value ENBConfigurationTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationTransferIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {ENBConfigurationTransferIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type ENBConfigurationTransferIEValueProtocolIEContainerList []ENBConfigurationTransferIEValueProtocolIESingleContainer

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
func BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEContainerList(v *s33.WriteReplaceWarningResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
func BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEContainerList(v *s33.WriteReplaceWarningResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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

// ENBConfigurationTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[ENBConfigurationTransferIEValueERABIEContainerList].
type ENBConfigurationTransferIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationTransferIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationTransferIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationTransferIEValueERABIEContainerListAPERValue) WithoutReplay() ENBConfigurationTransferIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationTransferIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{ENBConfigurationTransferIEs}} of TS 36.413: a single information element field.
type ENBConfigurationTransferIEValueProtocolIESingleContainer = ENBConfigurationTransferIEField

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
func BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIESingleContainer(v *s33.WriteReplaceWarningResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIESingleContainer(v *s33.WriteReplaceWarningResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
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

// ENBConfigurationTransferIEFieldAPERValue is the concrete APERValue[ENBConfigurationTransferIEField].
type ENBConfigurationTransferIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationTransferIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationTransferIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationTransferIEFieldAPERValue) WithoutReplay() ENBConfigurationTransferIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationTransferIEContainerAPERValue is the concrete APERValue[ENBConfigurationTransferIEContainer].
type ENBConfigurationTransferIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationTransferIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationTransferIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationTransferIEContainerAPERValue) WithoutReplay() ENBConfigurationTransferIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ENBConfigurationTransferIEValueProtocolErrorIEContainerList].
type ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationTransferIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ENBConfigurationTransferIEValueProtocolIEContainerList].
type ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ENBConfigurationTransferIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue) WithoutReplay() ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue {
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
	bodyHandoverCommand                    *s41.HandoverCommand
	bodyHandoverRequestAcknowledge         *s39.HandoverRequestAcknowledge
	bodyPathSwitchRequestAcknowledge       *s48.PathSwitchRequestAcknowledge
	bodyHandoverCancelAcknowledge          *s25.HandoverCancelAcknowledge
	bodyERABSetupResponse                  *s47.ERABSetupResponse
	bodyERABModifyResponse                 *s46.ERABModifyResponse
	bodyERABReleaseResponse                *s46.ERABReleaseResponse
	bodyInitialContextSetupResponse        *s40.InitialContextSetupResponse
	bodyResetAcknowledge                   *s45.ResetAcknowledge
	bodyS1SetupResponse                    *s44.S1SetupResponse
	bodyUEContextModificationResponse      *s37.UEContextModificationResponse
	bodyUEContextReleaseComplete           *s47.UEContextReleaseComplete
	bodyENBConfigurationUpdateAcknowledge  *s24.ENBConfigurationUpdateAcknowledge
	bodyMMEConfigurationUpdateAcknowledge  *s25.MMEConfigurationUpdateAcknowledge
	bodyWriteReplaceWarningResponse        *WriteReplaceWarningResponse
	bodyKillResponse                       *s33.KillResponse
	bodyUERadioCapabilityMatchResponse     *s37.UERadioCapabilityMatchResponse
	bodyERABModificationConfirm            *s40.ERABModificationConfirm
	bodyUEContextModificationConfirm       *s36.UEContextModificationConfirm
	bodyUEContextSuspendResponse           *s37.UEContextSuspendResponse
	bodyUEContextResumeResponse            *s39.UEContextResumeResponse
	bodyUERadioCapabilityIDMappingResponse *s37.UERadioCapabilityIDMappingResponse
	bodyS1RemovalResponse                  *s27.S1RemovalResponse
}

// Opaque returns the retained opaque open value of SuccessfulValue and reports whether the opaque alternative is selected.
func (v *SuccessfulValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}

// AsHandoverCommand returns the selected HandoverCommand value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsHandoverCommand() (*s41.HandoverCommand, bool) {
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
func (v *SuccessfulValue) AsPathSwitchRequestAcknowledge() (*s48.PathSwitchRequestAcknowledge, bool) {
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
func (v *SuccessfulValue) AsERABSetupResponse() (*s47.ERABSetupResponse, bool) {
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
func (v *SuccessfulValue) AsResetAcknowledge() (*s45.ResetAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(14) || v.bodyResetAcknowledge == nil {
		return nil, false
	}
	return v.bodyResetAcknowledge, true
}

// AsS1SetupResponse returns the selected S1SetupResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsS1SetupResponse() (*s44.S1SetupResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(17) || v.bodyS1SetupResponse == nil {
		return nil, false
	}
	return v.bodyS1SetupResponse, true
}

// AsUEContextModificationResponse returns the selected UEContextModificationResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUEContextModificationResponse() (*s37.UEContextModificationResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(21) || v.bodyUEContextModificationResponse == nil {
		return nil, false
	}
	return v.bodyUEContextModificationResponse, true
}

// AsUEContextReleaseComplete returns the selected UEContextReleaseComplete value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUEContextReleaseComplete() (*s47.UEContextReleaseComplete, bool) {
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
func (v *SuccessfulValue) AsERABModificationConfirm() (*s40.ERABModificationConfirm, bool) {
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
func (v *SuccessfulValue) AsUEContextSuspendResponse() (*s37.UEContextSuspendResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(55) || v.bodyUEContextSuspendResponse == nil {
		return nil, false
	}
	return v.bodyUEContextSuspendResponse, true
}

// AsUEContextResumeResponse returns the selected UEContextResumeResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUEContextResumeResponse() (*s39.UEContextResumeResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(56) || v.bodyUEContextResumeResponse == nil {
		return nil, false
	}
	return v.bodyUEContextResumeResponse, true
}

// AsUERadioCapabilityIDMappingResponse returns the selected UERadioCapabilityIDMappingResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUERadioCapabilityIDMappingResponse() (*s37.UERadioCapabilityIDMappingResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(63) || v.bodyUERadioCapabilityIDMappingResponse == nil {
		return nil, false
	}
	return v.bodyUERadioCapabilityIDMappingResponse, true
}

// AsS1RemovalResponse returns the selected S1RemovalResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsS1RemovalResponse() (*s27.S1RemovalResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(67) || v.bodyS1RemovalResponse == nil {
		return nil, false
	}
	return v.bodyS1RemovalResponse, true
}
func BridgeDecodeSuccessfulValue(code s00.ProcedureCode, raw aper.OpaqueOpenType) (SuccessfulValue, error) {
	v := SuccessfulValue{code: code}
	switch code {
	case s00.ProcedureCode(0):
		var body s41.HandoverCommand
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s41.BridgeHandoverCommandMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.HandoverCommand:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverCommand")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s41.BridgeHandoverCommandFieldPerPadding(&body) = padding
		*s41.BridgeHandoverCommandFieldReceived(&body) = true
		raw.RetainContents(s41.BridgeHandoverCommandFieldReceivedBytes(&body))
		*s41.BridgeHandoverCommandFieldReceivedLocation(&body) = raw.ContentLocation()
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
		var body s48.PathSwitchRequestAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s48.BridgePathSwitchRequestAcknowledgeMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.PathSwitchRequestAcknowledge:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PathSwitchRequestAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s48.BridgePathSwitchRequestAcknowledgeFieldPerPadding(&body) = padding
		*s48.BridgePathSwitchRequestAcknowledgeFieldReceived(&body) = true
		raw.RetainContents(s48.BridgePathSwitchRequestAcknowledgeFieldReceivedBytes(&body))
		*s48.BridgePathSwitchRequestAcknowledgeFieldReceivedLocation(&body) = raw.ContentLocation()
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
		var body s47.ERABSetupResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s47.BridgeERABSetupResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ERABSetupResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABSetupResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s47.BridgeERABSetupResponseFieldPerPadding(&body) = padding
		*s47.BridgeERABSetupResponseFieldReceived(&body) = true
		raw.RetainContents(s47.BridgeERABSetupResponseFieldReceivedBytes(&body))
		*s47.BridgeERABSetupResponseFieldReceivedLocation(&body) = raw.ContentLocation()
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
		var body s45.ResetAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s45.BridgeResetAcknowledgeMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ResetAcknowledge:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ResetAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s45.BridgeResetAcknowledgeFieldPerPadding(&body) = padding
		*s45.BridgeResetAcknowledgeFieldReceived(&body) = true
		raw.RetainContents(s45.BridgeResetAcknowledgeFieldReceivedBytes(&body))
		*s45.BridgeResetAcknowledgeFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyResetAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(17):
		var body s44.S1SetupResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s44.BridgeS1SetupResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.S1SetupResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "S1SetupResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s44.BridgeS1SetupResponseFieldPerPadding(&body) = padding
		*s44.BridgeS1SetupResponseFieldReceived(&body) = true
		raw.RetainContents(s44.BridgeS1SetupResponseFieldReceivedBytes(&body))
		*s44.BridgeS1SetupResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyS1SetupResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(21):
		var body s37.UEContextModificationResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s37.BridgeUEContextModificationResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UEContextModificationResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextModificationResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s37.BridgeUEContextModificationResponseFieldPerPadding(&body) = padding
		*s37.BridgeUEContextModificationResponseFieldReceived(&body) = true
		raw.RetainContents(s37.BridgeUEContextModificationResponseFieldReceivedBytes(&body))
		*s37.BridgeUEContextModificationResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextModificationResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(23):
		var body s47.UEContextReleaseComplete
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s47.BridgeUEContextReleaseCompleteMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UEContextReleaseComplete:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextReleaseComplete")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s47.BridgeUEContextReleaseCompleteFieldPerPadding(&body) = padding
		*s47.BridgeUEContextReleaseCompleteFieldReceived(&body) = true
		raw.RetainContents(s47.BridgeUEContextReleaseCompleteFieldReceivedBytes(&body))
		*s47.BridgeUEContextReleaseCompleteFieldReceivedLocation(&body) = raw.ContentLocation()
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
		var body s40.ERABModificationConfirm
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s40.BridgeERABModificationConfirmMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ERABModificationConfirm:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABModificationConfirm")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s40.BridgeERABModificationConfirmFieldPerPadding(&body) = padding
		*s40.BridgeERABModificationConfirmFieldReceived(&body) = true
		raw.RetainContents(s40.BridgeERABModificationConfirmFieldReceivedBytes(&body))
		*s40.BridgeERABModificationConfirmFieldReceivedLocation(&body) = raw.ContentLocation()
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
		var body s37.UEContextSuspendResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s37.BridgeUEContextSuspendResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UEContextSuspendResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextSuspendResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s37.BridgeUEContextSuspendResponseFieldPerPadding(&body) = padding
		*s37.BridgeUEContextSuspendResponseFieldReceived(&body) = true
		raw.RetainContents(s37.BridgeUEContextSuspendResponseFieldReceivedBytes(&body))
		*s37.BridgeUEContextSuspendResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextSuspendResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(56):
		var body s39.UEContextResumeResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s39.BridgeUEContextResumeResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UEContextResumeResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextResumeResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s39.BridgeUEContextResumeResponseFieldPerPadding(&body) = padding
		*s39.BridgeUEContextResumeResponseFieldReceived(&body) = true
		raw.RetainContents(s39.BridgeUEContextResumeResponseFieldReceivedBytes(&body))
		*s39.BridgeUEContextResumeResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextResumeResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(63):
		var body s37.UERadioCapabilityIDMappingResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s37.BridgeUERadioCapabilityIDMappingResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UERadioCapabilityIDMappingResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UERadioCapabilityIDMappingResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s37.BridgeUERadioCapabilityIDMappingResponseFieldPerPadding(&body) = padding
		*s37.BridgeUERadioCapabilityIDMappingResponseFieldReceived(&body) = true
		raw.RetainContents(s37.BridgeUERadioCapabilityIDMappingResponseFieldReceivedBytes(&body))
		*s37.BridgeUERadioCapabilityIDMappingResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUERadioCapabilityIDMappingResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(67):
		var body s27.S1RemovalResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s27.BridgeS1RemovalResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.S1RemovalResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "S1RemovalResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s27.BridgeS1RemovalResponseFieldPerPadding(&body) = padding
		*s27.BridgeS1RemovalResponseFieldReceived(&body) = true
		raw.RetainContents(s27.BridgeS1RemovalResponseFieldReceivedBytes(&body))
		*s27.BridgeS1RemovalResponseFieldReceivedLocation(&body) = raw.ContentLocation()
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
		return s41.BridgeHandoverCommandMethodMarshalAPERBudget(v.bodyHandoverCommand, budget, fresh)
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
		return s48.BridgePathSwitchRequestAcknowledgeMethodMarshalAPERBudget(v.bodyPathSwitchRequestAcknowledge, budget, fresh)
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
		return s47.BridgeERABSetupResponseMethodMarshalAPERBudget(v.bodyERABSetupResponse, budget, fresh)
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
		return s45.BridgeResetAcknowledgeMethodMarshalAPERBudget(v.bodyResetAcknowledge, budget, fresh)
	case s00.ProcedureCode(17):
		if v.bodyS1SetupResponse == nil {
			return nil, fmt.Errorf("%s value: missing S1SetupResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s44.BridgeS1SetupResponseMethodMarshalAPERBudget(v.bodyS1SetupResponse, budget, fresh)
	case s00.ProcedureCode(21):
		if v.bodyUEContextModificationResponse == nil {
			return nil, fmt.Errorf("%s value: missing UEContextModificationResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s37.BridgeUEContextModificationResponseMethodMarshalAPERBudget(v.bodyUEContextModificationResponse, budget, fresh)
	case s00.ProcedureCode(23):
		if v.bodyUEContextReleaseComplete == nil {
			return nil, fmt.Errorf("%s value: missing UEContextReleaseComplete", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s47.BridgeUEContextReleaseCompleteMethodMarshalAPERBudget(v.bodyUEContextReleaseComplete, budget, fresh)
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
		return s40.BridgeERABModificationConfirmMethodMarshalAPERBudget(v.bodyERABModificationConfirm, budget, fresh)
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
		return s37.BridgeUEContextSuspendResponseMethodMarshalAPERBudget(v.bodyUEContextSuspendResponse, budget, fresh)
	case s00.ProcedureCode(56):
		if v.bodyUEContextResumeResponse == nil {
			return nil, fmt.Errorf("%s value: missing UEContextResumeResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s39.BridgeUEContextResumeResponseMethodMarshalAPERBudget(v.bodyUEContextResumeResponse, budget, fresh)
	case s00.ProcedureCode(63):
		if v.bodyUERadioCapabilityIDMappingResponse == nil {
			return nil, fmt.Errorf("%s value: missing UERadioCapabilityIDMappingResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s37.BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERBudget(v.bodyUERadioCapabilityIDMappingResponse, budget, fresh)
	case s00.ProcedureCode(67):
		if v.bodyS1RemovalResponse == nil {
			return nil, fmt.Errorf("%s value: missing S1RemovalResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s27.BridgeS1RemovalResponseMethodMarshalAPERBudget(v.bodyS1RemovalResponse, budget, fresh)
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
func BridgeCaptureS1APENBConfigurationTransferIEValue(v *ENBConfigurationTransferIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(129):
			{
				f := s.Begin()
				s.Bool(v.rowSONConfigurationTransferECT == nil)
				if v.rowSONConfigurationTransferECT != nil {
					BridgeCaptureS1APSONConfigurationTransfer(v.rowSONConfigurationTransferECT, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(294):
			{
				f := s.Begin()
				s.Bool(v.rowENDCSONConfigurationTransferECT == nil)
				if v.rowENDCSONConfigurationTransferECT != nil {
					BridgeCaptureS1APENDCSONConfigurationTransfer(v.rowENDCSONConfigurationTransferECT, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(310):
			{
				f := s.Begin()
				s.Bool(v.rowIntersystemSONConfigurationTransferECT == nil)
				if v.rowIntersystemSONConfigurationTransferECT != nil {
					s00.BridgeCaptureS1APIntersystemSONConfigurationTransfer(v.rowIntersystemSONConfigurationTransferECT, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBConfigurationTransferIEValue) captureSemantics(s aper.SemanticCapture) ENBConfigurationTransferIEValue {
	BridgeCaptureS1APENBConfigurationTransferIEValue(&v, &s)
	return v
}
func BridgeCompareS1APENBConfigurationTransferIEValue(v *ENBConfigurationTransferIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(129):
			{
				f := s.Begin()
				s.Bool(v.rowSONConfigurationTransferECT == nil)
				if v.rowSONConfigurationTransferECT != nil {
					BridgeCompareS1APSONConfigurationTransfer(v.rowSONConfigurationTransferECT, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(294):
			{
				f := s.Begin()
				s.Bool(v.rowENDCSONConfigurationTransferECT == nil)
				if v.rowENDCSONConfigurationTransferECT != nil {
					BridgeCompareS1APENDCSONConfigurationTransfer(v.rowENDCSONConfigurationTransferECT, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(310):
			{
				f := s.Begin()
				s.Bool(v.rowIntersystemSONConfigurationTransferECT == nil)
				if v.rowIntersystemSONConfigurationTransferECT != nil {
					s02.BridgeCompareS1APIntersystemSONConfigurationTransfer(v.rowIntersystemSONConfigurationTransferECT, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ENBConfigurationTransferIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APENBConfigurationTransferIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APENDCSONConfigurationTransfer(v *ENDCSONConfigurationTransfer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCaptureS1APENDCSONTransferType(&v.Transfertype, s)
	BridgeCaptureS1APSONInformation(&v.SONInformation, s)
	{
		f := s.Begin()
		s.Bool(v.X2TNLConfigInfo == nil)
		if v.X2TNLConfigInfo != nil {
			BridgeCaptureS1APX2TNLConfigurationInfo(v.X2TNLConfigInfo, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeENDCSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENDCSONConfigurationTransfer(v *ENDCSONConfigurationTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s32.BridgeCompareS1APENDCSONTransferType(&v.Transfertype, s)
	BridgeCompareS1APSONInformation(&v.SONInformation, s)
	{
		f := s.Begin()
		s.Bool(v.X2TNLConfigInfo == nil)
		if v.X2TNLConfigInfo != nil {
			BridgeCompareS1APX2TNLConfigurationInfo(v.X2TNLConfigInfo, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s13.BridgeENDCSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APSONConfigurationTransfer(v *SONConfigurationTransfer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s34.BridgeCaptureS1APTargeteNBID(&v.TargeteNBID, s)
	s32.BridgeCaptureS1APSourceeNBID(&v.SourceeNBID, s)
	BridgeCaptureS1APSONInformation(&v.SONInformation, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APSONConfigurationTransfer(v *SONConfigurationTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s34.BridgeCompareS1APTargeteNBID(&v.TargeteNBID, s)
	s32.BridgeCompareS1APSourceeNBID(&v.SourceeNBID, s)
	BridgeCompareS1APSONInformation(&v.SONInformation, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
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
func BridgeCaptureS1APSONInformation(v *SONInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	{
		f := s.Begin()
		s.Bool(v.UnknownExtension == nil)
		if v.UnknownExtension != nil {
			s.ChoiceExtension(v.UnknownExtension)
		}
		s.End(f, nil, false)
	}
	switch v.Choice {
	case s00.SONInformationChoiceSONInformationRequest:
		{
			f := s.Begin()
			s.Bool(v.SONInformationRequest == nil)
			if v.SONInformationRequest != nil {
				s00.BridgeCaptureS1APSONInformationRequest(v.SONInformationRequest, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONInformationChoiceSONInformationReply:
		{
			f := s.Begin()
			s.Bool(v.SONInformationReply == nil)
			if v.SONInformationReply != nil {
				BridgeCaptureS1APSONInformationReply(v.SONInformationReply, s)
			}
			s.End(f, nil, false)
		}
	case s00.SONInformationChoiceSONInformationExtension:
		{
			f := s.Begin()
			s.Bool(v.SONInformationExtension == nil)
			if v.SONInformationExtension != nil {
				s20.BridgeCaptureS1APSONInformationExtension(v.SONInformationExtension, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 2 {
		s.CheckChoice(v.replay, v.stream)
	}
}
func BridgeCompareS1APSONInformation(v *SONInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64(v.Choice))
	{
		f := s.Begin()
		s.Bool(v.UnknownExtension == nil)
		if v.UnknownExtension != nil {
			s.ChoiceExtension(v.UnknownExtension)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	switch v.Choice {
	case s00.SONInformationChoiceSONInformationRequest:
		{
			f := s.Begin()
			s.Bool(v.SONInformationRequest == nil)
			if v.SONInformationRequest != nil {
				s06.BridgeCompareS1APSONInformationRequest(v.SONInformationRequest, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONInformationChoiceSONInformationReply:
		{
			f := s.Begin()
			s.Bool(v.SONInformationReply == nil)
			if v.SONInformationReply != nil {
				BridgeCompareS1APSONInformationReply(v.SONInformationReply, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.SONInformationChoiceSONInformationExtension:
		{
			f := s.Begin()
			s.Bool(v.SONInformationExtension == nil)
			if v.SONInformationExtension != nil {
				s20.BridgeCompareS1APSONInformationExtension(v.SONInformationExtension, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
	if v.UnknownExtension == nil && v.Choice > 2 {
		s.CheckChoice(v.replay, v.stream)
	}
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
	s35.BridgeSONInformationReplyExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s35.BridgeSONInformationReplyExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
					s41.BridgeCaptureS1APHandoverCommand(v.bodyHandoverCommand, s)
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
					s48.BridgeCaptureS1APPathSwitchRequestAcknowledge(v.bodyPathSwitchRequestAcknowledge, s)
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
					s47.BridgeCaptureS1APERABSetupResponse(v.bodyERABSetupResponse, s)
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
					s45.BridgeCaptureS1APResetAcknowledge(v.bodyResetAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(17):
			{
				f := s.Begin()
				s.Bool(v.bodyS1SetupResponse == nil)
				if v.bodyS1SetupResponse != nil {
					s44.BridgeCaptureS1APS1SetupResponse(v.bodyS1SetupResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationResponse == nil)
				if v.bodyUEContextModificationResponse != nil {
					s37.BridgeCaptureS1APUEContextModificationResponse(v.bodyUEContextModificationResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(23):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextReleaseComplete == nil)
				if v.bodyUEContextReleaseComplete != nil {
					s47.BridgeCaptureS1APUEContextReleaseComplete(v.bodyUEContextReleaseComplete, s)
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
					s40.BridgeCaptureS1APERABModificationConfirm(v.bodyERABModificationConfirm, s)
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
					s37.BridgeCaptureS1APUEContextSuspendResponse(v.bodyUEContextSuspendResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(56):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextResumeResponse == nil)
				if v.bodyUEContextResumeResponse != nil {
					s39.BridgeCaptureS1APUEContextResumeResponse(v.bodyUEContextResumeResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(63):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityIDMappingResponse == nil)
				if v.bodyUERadioCapabilityIDMappingResponse != nil {
					s37.BridgeCaptureS1APUERadioCapabilityIDMappingResponse(v.bodyUERadioCapabilityIDMappingResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(67):
			{
				f := s.Begin()
				s.Bool(v.bodyS1RemovalResponse == nil)
				if v.bodyS1RemovalResponse != nil {
					s27.BridgeCaptureS1APS1RemovalResponse(v.bodyS1RemovalResponse, s)
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
					s41.BridgeCompareS1APHandoverCommand(v.bodyHandoverCommand, s)
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
					s48.BridgeCompareS1APPathSwitchRequestAcknowledge(v.bodyPathSwitchRequestAcknowledge, s)
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
					s47.BridgeCompareS1APERABSetupResponse(v.bodyERABSetupResponse, s)
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
					s45.BridgeCompareS1APResetAcknowledge(v.bodyResetAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(17):
			{
				f := s.Begin()
				s.Bool(v.bodyS1SetupResponse == nil)
				if v.bodyS1SetupResponse != nil {
					s44.BridgeCompareS1APS1SetupResponse(v.bodyS1SetupResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationResponse == nil)
				if v.bodyUEContextModificationResponse != nil {
					s37.BridgeCompareS1APUEContextModificationResponse(v.bodyUEContextModificationResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(23):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextReleaseComplete == nil)
				if v.bodyUEContextReleaseComplete != nil {
					s47.BridgeCompareS1APUEContextReleaseComplete(v.bodyUEContextReleaseComplete, s)
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
					s40.BridgeCompareS1APERABModificationConfirm(v.bodyERABModificationConfirm, s)
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
					s37.BridgeCompareS1APUEContextSuspendResponse(v.bodyUEContextSuspendResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(56):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextResumeResponse == nil)
				if v.bodyUEContextResumeResponse != nil {
					s39.BridgeCompareS1APUEContextResumeResponse(v.bodyUEContextResumeResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(63):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityIDMappingResponse == nil)
				if v.bodyUERadioCapabilityIDMappingResponse != nil {
					s37.BridgeCompareS1APUERadioCapabilityIDMappingResponse(v.bodyUERadioCapabilityIDMappingResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(67):
			{
				f := s.Begin()
				s.Bool(v.bodyS1RemovalResponse == nil)
				if v.bodyS1RemovalResponse != nil {
					s27.BridgeCompareS1APS1RemovalResponse(v.bodyS1RemovalResponse, s)
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

// ENDCSONConfigurationTransfer represents the ASN.1 type EN-DCSONConfigurationTransfer (SEQUENCE).
type ENDCSONConfigurationTransfer struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	Transfertype      s32.ENDCSONTransferType                            `asn1:"tag:0,context,explicit"`
	SONInformation    SONInformation                                     `asn1:"tag:1,context,explicit"`
	X2TNLConfigInfo   *X2TNLConfigurationInfo                            `asn1:"tag:2,context,implicit,optional" json:"X2TNLConfigInfo,omitempty"`
	IEExtensions      s08.ENDCSONConfigurationTransferExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                               `asn1:"-" json:"-"`
	extCount          int64                                              `asn1:"-" json:"-"`
	extPresent        []bool                                             `asn1:"-" json:"-"`
	extData           [][]byte                                           `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// SONInformation represents the ASN.1 CHOICE type SONInformation.
type SONInformation struct {
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	received                bool
	withoutReplay           bool
	receivedAbsolute        bool
	receivedBytes           aper.WireSpan
	receivedLocation        aper.Location
	Choice                  int
	perPadding              aper.CompletePadding         `json:"-"`
	perOpenTypePadding      aper.CompletePadding         `json:"-"`
	UnknownExtension        *aper.ChoiceExtension        `json:"UnknownExtension,omitempty"`
	SONInformationRequest   *s00.SONInformationRequest   `json:"SONInformationRequest,omitempty"`
	SONInformationReply     *SONInformationReply         `json:"SONInformationReply,omitempty"`
	SONInformationExtension *s20.SONInformationExtension `json:"SONInformationExtension,omitempty"`
}

// NewSONInformationSONInformationRequest creates a SONInformation with the sONInformationRequest alternative.
func BridgeNewSONInformationSONInformationRequestLegacy(v s00.SONInformationRequest) SONInformation {
	return SONInformation{
		Choice:                s00.SONInformationChoiceSONInformationRequest,
		SONInformationRequest: &v,
	}
}

// NewSONInformationSONInformationReply creates a SONInformation with the sONInformationReply alternative.
func BridgeNewSONInformationSONInformationReplyLegacy(v SONInformationReply) SONInformation {
	return SONInformation{
		Choice:              s00.SONInformationChoiceSONInformationReply,
		SONInformationReply: &v,
	}
}

// NewSONInformationSONInformationExtension creates a SONInformation with the sONInformation-Extension alternative.
func BridgeNewSONInformationSONInformationExtensionLegacy(v s20.SONInformationExtension) SONInformation {
	return SONInformation{
		Choice:                  s00.SONInformationChoiceSONInformationExtension,
		SONInformationExtension: &v,
	}
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
	IEExtensions           s35.SONInformationReplyExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef      bool                                      `asn1:"-" json:"-"`
	extCount               int64                                     `asn1:"-" json:"-"`
	extPresent             []bool                                    `asn1:"-" json:"-"`
	extData                [][]byte                                  `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
}

// SONConfigurationTransfer represents the ASN.1 type SONConfigurationTransfer (SEQUENCE).
type SONConfigurationTransfer struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	TargeteNBID       s34.TargeteNBID                            `asn1:"tag:0,context,implicit"`
	SourceeNBID       s32.SourceeNBID                            `asn1:"tag:1,context,implicit"`
	SONInformation    SONInformation                             `asn1:"tag:2,context,explicit"`
	IEExtensions      SONConfigurationTransferExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                       `asn1:"-" json:"-"`
	extCount          int64                                      `asn1:"-" json:"-"`
	extPresent        []bool                                     `asn1:"-" json:"-"`
	extData           [][]byte                                   `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                          `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                     `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
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
	IEExtensions                      s39.X2TNLConfigurationInfoExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                 bool                                         `asn1:"-" json:"-"`
	extCount                          int64                                        `asn1:"-" json:"-"`
	extPresent                        []bool                                       `asn1:"-" json:"-"`
	extData                           [][]byte                                     `asn1:"-" json:"-"`
	perPadding                        aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding                     []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin                         []aper.OpaqueOrigin
	extWire                           []aper.WireSpan
}

// MarshalAPER encodes ENDCSONConfigurationTransfer to APER format.
func (v *ENDCSONConfigurationTransfer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ENDCSONConfigurationTransfer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.X2TNLConfigInfo != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := s32.BridgeENDCSONTransferTypeMethodMarshalAPERTo(&v.Transfertype, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding transfertype: %w", err)
	}
	if err := v.SONInformation.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding sONInformation: %w", err)
	}
	if v.X2TNLConfigInfo != nil {
		if err := v.X2TNLConfigInfo.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding x2TNLConfigInfo: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s08.BridgeENDCSONConfigurationTransferExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENDCSONConfigurationTransfer from APER format.
func (v *ENDCSONConfigurationTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENDCSONConfigurationTransfer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ENDCSONConfigurationTransfer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENDCSONConfigurationTransfer")
	}
	bb.EnterComponent("ENDCSONConfigurationTransfer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ENDCSONConfigurationTransfer")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENDCSONConfigurationTransfer")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENDCSONConfigurationTransfer")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ENDCSONConfigurationTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCSONConfigurationTransfer{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_x2tnlconfiginfo, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_transfertype := bb.EnterComponent("Transfertype")
	if err := s32.BridgeENDCSONTransferTypeMethodUnmarshalAPERFrom(&v.Transfertype, bb); err != nil {
		return runtime.WrapDecodePath(err, "Transfertype")
	}
	bb.LeaveComponent(toleranceMark_transfertype)
	toleranceMark_soninformation := bb.EnterComponent("SONInformation")
	if err := v.SONInformation.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONInformation")
	}
	bb.LeaveComponent(toleranceMark_soninformation)
	if opt_x2tnlconfiginfo {
		toleranceMark_x2tnlconfiginfo := bb.EnterComponent("X2TNLConfigInfo")
		var dec_x2tnlconfiginfo X2TNLConfigurationInfo
		if err := dec_x2tnlconfiginfo.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "X2TNLConfigInfo")
		}
		if err := aper.ChargeValue(bb, dec_x2tnlconfiginfo); err != nil {
			return err
		}
		v.X2TNLConfigInfo = &dec_x2tnlconfiginfo
		bb.LeaveComponent(toleranceMark_x2tnlconfiginfo)
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s08.ENDCSONConfigurationTransferExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s08.ENDCSONConfigurationTransferExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s08.BridgeENDCSONConfigurationTransferExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes SONInformation to APER format.
func (v *SONInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SONInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "SONInformation:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "SONInformation:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 1 {
			return fmt.Errorf("%s extension index %d is known to this schema", "SONInformation:", v.UnknownExtension.Index())
		}
		if err := aper.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index()); err != nil {
			return err
		}
		return v.UnknownExtension.EncodeTo(bb)
	}
	if v.Choice < 1 {
		return fmt.Errorf("%s choice %d must be positive", "SONInformation:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 2 {
			return fmt.Errorf("extension choice index outside root")
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-2-1)); err != nil {
			return err
		}
		inner := aper.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case s00.SONInformationChoiceSONInformationExtension:
			if v.SONInformationExtension == nil {
				return fmt.Errorf("choice alternative sONInformation-Extension is nil")
			}
			if err := s20.BridgeSONInformationExtensionMethodMarshalAPERTo(v.SONInformationExtension, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding sONInformation-Extension: %w", err)
			}
		default:
			return fmt.Errorf("unknown SONInformation extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(s07.BridgeFreshCompletePadding(v.perOpenTypePadding, fresh...))
		if err != nil {
			return err
		}
		if err := aper.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.SONInformationChoiceSONInformationRequest:
		if v.SONInformationRequest == nil {
			return fmt.Errorf("choice alternative sONInformationRequest is nil")
		}
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.SONInformationRequest), 1, true); err != nil {
			return fmt.Errorf("encoding sONInformationRequest: %w", err)
		}
	case s00.SONInformationChoiceSONInformationReply:
		if v.SONInformationReply == nil {
			return fmt.Errorf("choice alternative sONInformationReply is nil")
		}
		if err := v.SONInformationReply.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding sONInformationReply: %w", err)
		}
	default:
		return fmt.Errorf("unknown SONInformation choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes SONInformation from APER format.
func (v *SONInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SONInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SONInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONInformation")
	}
	bb.EnterComponent("SONInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "SONInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONInformation")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SONInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONInformation{}
	isExtension, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := aper.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := aper.DecodeChoiceExtensionAligned(bb, extIdx)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		if extIdx >= 1 {
			if err := openExtension.ObserveUnknown(bb); err != nil {
				return err
			}
			v.UnknownExtension = &openExtension
			v.stream = bb.CaptureWireSpan(replayStart)

			return nil
		}
		inner := openExtension.ChildDecodeBuffer(bb)
		if err := inner.EnterOpenType(); err != nil {
			return err
		}
		defer inner.LeaveOpenType()
		// arithmetic pattern APER_CHOICE_EXT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:206
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(2) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 2 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case s00.SONInformationChoiceSONInformationExtension:
			extensionPath = "SONInformationExtension"
			toleranceMark_soninformationextension := inner.EnterComponent("SONInformationExtension")
			var dec_soninformationextension s20.SONInformationExtension
			if err := s20.BridgeSONInformationExtensionMethodUnmarshalAPERFrom(&dec_soninformationextension, inner); err != nil {
				return runtime.WrapDecodePath(err, "SONInformationExtension")
			}
			if err := aper.ChargeValue(inner, dec_soninformationextension); err != nil {
				return err
			}
			v.SONInformationExtension = &dec_soninformationextension
			inner.LeaveComponent(toleranceMark_soninformationextension)
		}
		paddingMark := inner.EnterComponent(extensionPath)
		padding, err := aper.CaptureOpenTypePadding(inner)
		inner.LeaveComponent(paddingMark)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.perOpenTypePadding = padding
		v.stream = bb.CaptureWireSpan(replayStart)

		return nil
	}
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.SONInformationChoiceSONInformationRequest:
		val_soninformationrequest, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 3, Path: "SONInformationRequest"})
		if err != nil {
			return runtime.WrapDecodePath(err, "SONInformationRequest")
		}
		tmp_soninformationrequest := s00.SONInformationRequest(val_soninformationrequest)
		if err := aper.ChargeValue(bb, tmp_soninformationrequest); err != nil {
			return err
		}
		v.SONInformationRequest = (*s00.SONInformationRequest)(bb.OwnInt64(int64(tmp_soninformationrequest)))

	case s00.SONInformationChoiceSONInformationReply:
		toleranceMark_soninformationreply := bb.EnterComponent("SONInformationReply")
		var dec_soninformationreply SONInformationReply
		if err := dec_soninformationreply.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "SONInformationReply")
		}
		if err := aper.ChargeValue(bb, dec_soninformationreply); err != nil {
			return err
		}
		v.SONInformationReply = &dec_soninformationreply
		bb.LeaveComponent(toleranceMark_soninformationreply)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
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
				if err := s35.BridgeSONInformationReplyExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		tmp_ieextensions := make(s35.SONInformationReplyExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s35.SONInformationReplyExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s35.BridgeSONInformationReplyExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes SONConfigurationTransfer to APER format.
func (v *SONConfigurationTransfer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SONConfigurationTransfer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := s34.BridgeTargeteNBIDMethodMarshalAPERTo(&v.TargeteNBID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding targeteNB-ID: %w", err)
	}
	if err := s32.BridgeSourceeNBIDMethodMarshalAPERTo(&v.SourceeNBID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding sourceeNB-ID: %w", err)
	}
	if err := v.SONInformation.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding sONInformation: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SONConfigurationTransfer from APER format.
func (v *SONConfigurationTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SONConfigurationTransfer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SONConfigurationTransfer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SONConfigurationTransfer")
	}
	bb.EnterComponent("SONConfigurationTransfer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONConfigurationTransfer")
	}
	padding, err := aper.CaptureFinalBits(bb, "SONConfigurationTransfer")
	if err != nil {
		return runtime.WrapDecodePath(err, "SONConfigurationTransfer")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SONConfigurationTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONConfigurationTransfer{}
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
	toleranceMark_targetenbid := bb.EnterComponent("TargeteNBID")
	if err := s34.BridgeTargeteNBIDMethodUnmarshalAPERFrom(&v.TargeteNBID, bb); err != nil {
		return runtime.WrapDecodePath(err, "TargeteNBID")
	}
	bb.LeaveComponent(toleranceMark_targetenbid)
	toleranceMark_sourceenbid := bb.EnterComponent("SourceeNBID")
	if err := s32.BridgeSourceeNBIDMethodUnmarshalAPERFrom(&v.SourceeNBID, bb); err != nil {
		return runtime.WrapDecodePath(err, "SourceeNBID")
	}
	bb.LeaveComponent(toleranceMark_sourceenbid)
	toleranceMark_soninformation := bb.EnterComponent("SONInformation")
	if err := v.SONInformation.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SONInformation")
	}
	bb.LeaveComponent(toleranceMark_soninformation)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(SONConfigurationTransferExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem SONConfigurationTransferExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := elem.unmarshalAPERFrom(bb); err != nil {
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
				if err := s39.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		tmp_ieextensions := make(s39.X2TNLConfigurationInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s39.X2TNLConfigurationInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s39.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ENDCSONConfigurationTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENDCSONConfigurationTransfer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENDCSONConfigurationTransfer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENDCSONConfigurationTransfer) WithoutReplay() ENDCSONConfigurationTransfer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENDCSONConfigurationTransfer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SONConfigurationTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONConfigurationTransfer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SONConfigurationTransfer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SONConfigurationTransfer) WithoutReplay() SONConfigurationTransfer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SONConfigurationTransfer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SONInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SONInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SONInformation) WithoutReplay() SONInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SONInformation
	v.perPadding = zero.perPadding
	return v
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
func (v *ENDCSONConfigurationTransfer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENDCSONConfigurationTransfer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCSONConfigurationTransfer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCSONConfigurationTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENDCSONConfigurationTransfer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCSONConfigurationTransfer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCSONConfigurationTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SONConfigurationTransfer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SONConfigurationTransfer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SONConfigurationTransfer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SONConfigurationTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SONConfigurationTransfer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SONConfigurationTransfer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SONConfigurationTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
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
func (v *ENDCSONConfigurationTransfer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENDCSONConfigurationTransfer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *ENDCSONConfigurationTransfer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENDCSONConfigurationTransfer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APENDCSONConfigurationTransfer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "ENDCSONConfigurationTransfer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "ENDCSONConfigurationTransfer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *ENDCSONConfigurationTransfer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "ENDCSONConfigurationTransfer")
}
func (v *ENDCSONConfigurationTransfer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "ENDCSONConfigurationTransfer")
}
func (v *ENDCSONConfigurationTransfer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APENDCSONConfigurationTransfer(v, &s)
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
func (v *ENDCSONConfigurationTransfer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *ENDCSONConfigurationTransfer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SONConfigurationTransfer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SONConfigurationTransfer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SONConfigurationTransfer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SONConfigurationTransfer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSONConfigurationTransfer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SONConfigurationTransfer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SONConfigurationTransfer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SONConfigurationTransfer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SONConfigurationTransfer")
}
func (v *SONConfigurationTransfer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SONConfigurationTransfer")
}
func (v *SONConfigurationTransfer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSONConfigurationTransfer(v, &s)
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
func (v *SONConfigurationTransfer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SONConfigurationTransfer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *SONInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SONInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *SONInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SONInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APSONInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "SONInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "SONInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *SONInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "SONInformation")
}
func (v *SONInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "SONInformation")
}
func (v *SONInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APSONInformation(v, &s)
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
func (v *SONInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *SONInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *ENDCSONConfigurationTransfer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENDCSONConfigurationTransfer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded ENDCSONConfigurationTransfer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APENDCSONConfigurationTransfer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = ENDCSONConfigurationTransfer{}
		return report, aper.OperationError(err, "ENDCSONConfigurationTransfer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENDCSONConfigurationTransfer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SONConfigurationTransfer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SONConfigurationTransfer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SONConfigurationTransfer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSONConfigurationTransfer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SONConfigurationTransfer{}
		return report, aper.OperationError(err, "SONConfigurationTransfer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SONConfigurationTransfer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *SONInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SONInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded SONInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APSONInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = SONInformation{}
		return report, aper.OperationError(err, "SONInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SONInformation")
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

// NewSONInformationSONInformationRequest constructs a checked complete value.
func NewSONInformationSONInformationRequest(v s00.SONInformationRequest, options ...aper.BuildOption) (SONInformation, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SONInformation{}, aper.OperationError(err, "SONInformationSONInformationRequest")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return SONInformation{}, aper.OperationError(err, "SONInformationSONInformationRequest")
	}
	value := BridgeNewSONInformationSONInformationRequestLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return SONInformation{}, aper.OperationError(err, "SONInformationSONInformationRequest")
	}
	return value, aper.OperationError(nil, "SONInformationSONInformationRequest")
}

// NewSONInformationSONInformationReply constructs a checked complete value.
func NewSONInformationSONInformationReply(v SONInformationReply, options ...aper.BuildOption) (SONInformation, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SONInformation{}, aper.OperationError(err, "SONInformationSONInformationReply")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return SONInformation{}, aper.OperationError(err, "SONInformationSONInformationReply")
	}
	value := BridgeNewSONInformationSONInformationReplyLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return SONInformation{}, aper.OperationError(err, "SONInformationSONInformationReply")
	}
	return value, aper.OperationError(nil, "SONInformationSONInformationReply")
}

// NewSONInformationSONInformationExtension constructs a checked complete value.
func NewSONInformationSONInformationExtension(v s20.SONInformationExtension, options ...aper.BuildOption) (SONInformation, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SONInformation{}, aper.OperationError(err, "SONInformationSONInformationExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return SONInformation{}, aper.OperationError(err, "SONInformationSONInformationExtension")
	}
	value := BridgeNewSONInformationSONInformationExtensionLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return SONInformation{}, aper.OperationError(err, "SONInformationSONInformationExtension")
	}
	return value, aper.OperationError(nil, "SONInformationSONInformationExtension")
}

// NewSONInformationUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewSONInformationUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (SONInformation, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return SONInformation{}, aper.OperationError(err, "SONInformationUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return SONInformation{}, aper.OperationError(err, "SONInformationUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return SONInformation{}, aper.OperationError(err, "SONInformationUnknownExtension")
	}
	value := SONInformation{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return SONInformation{}, aper.OperationError(err, "SONInformationUnknownExtension")
	}
	return value, aper.OperationError(nil, "SONInformationUnknownExtension")
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
	ProtocolIEs      s33.WriteReplaceWarningResponseIEContainer `asn1:"tag:0,context,implicit"`
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
			if err := s33.BridgeWriteReplaceWarningResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	v.ProtocolIEs = make(s33.WriteReplaceWarningResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s33.WriteReplaceWarningResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s33.BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type ENBConfigurationTransferIEValue struct {
	id                                        s00.ProtocolIEID
	received                                  aper.WireSpan
	replay                                    aper.Snapshot
	opaque                                    aper.OpaqueOpenType
	isOpaque                                  bool
	rowSONConfigurationTransferECT            *SONConfigurationTransfer
	rowENDCSONConfigurationTransferECT        *ENDCSONConfigurationTransfer
	rowIntersystemSONConfigurationTransferECT *s00.IntersystemSONConfigurationTransfer
}

func (v ENBConfigurationTransferIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(129):
		return v.rowSONConfigurationTransferECT != nil
	case s00.ProtocolIEID(294):
		return v.rowENDCSONConfigurationTransferECT != nil
	case s00.ProtocolIEID(310):
		return v.rowIntersystemSONConfigurationTransferECT != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ENBConfigurationTransferIEValue and reports whether the opaque alternative is selected.
func (v *ENBConfigurationTransferIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ENBConfigurationTransferIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ENBConfigurationTransferIEs"}}
}
func (ENBConfigurationTransferIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(129):
		return aper.UnknownSelector
	case s00.ProtocolIEID(294):
		return aper.UnknownSelector
	case s00.ProtocolIEID(310):
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
	case s00.ProtocolIEID(152):
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
	case s00.ProtocolIEID(209):
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
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsSONConfigurationTransferECT returns the selected SONConfigurationTransferECT value of ENBConfigurationTransferIEValue and reports whether that alternative is active.
func (v *ENBConfigurationTransferIEValue) AsSONConfigurationTransferECT() (*SONConfigurationTransfer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(129) || v.rowSONConfigurationTransferECT == nil {
		return nil, false
	}
	return v.rowSONConfigurationTransferECT, true
}

// AsENDCSONConfigurationTransferECT returns the selected ENDCSONConfigurationTransferECT value of ENBConfigurationTransferIEValue and reports whether that alternative is active.
func (v *ENBConfigurationTransferIEValue) AsENDCSONConfigurationTransferECT() (*ENDCSONConfigurationTransfer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(294) || v.rowENDCSONConfigurationTransferECT == nil {
		return nil, false
	}
	return v.rowENDCSONConfigurationTransferECT, true
}

// AsIntersystemSONConfigurationTransferECT returns the selected IntersystemSONConfigurationTransferECT value of ENBConfigurationTransferIEValue and reports whether that alternative is active.
func (v *ENBConfigurationTransferIEValue) AsIntersystemSONConfigurationTransferECT() (*s00.IntersystemSONConfigurationTransfer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(310) || v.rowIntersystemSONConfigurationTransferECT == nil {
		return nil, false
	}
	return v.rowIntersystemSONConfigurationTransferECT, true
}
func (v ENBConfigurationTransferIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ENBConfigurationTransferIEValue, error) {
	out := ENBConfigurationTransferIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(129):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value SONConfigurationTransfer
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SONConfigurationTransferECT:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SONConfigurationTransfer")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowSONConfigurationTransferECT = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(294):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ENDCSONConfigurationTransfer
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ENDCSONConfigurationTransferECT:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENDCSONConfigurationTransfer")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowENDCSONConfigurationTransferECT = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(310):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.IntersystemSONConfigurationTransfer, error) {
			var v struct {
				Value s00.IntersystemSONConfigurationTransfer
			}
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.IntersystemSONConfigurationTransfer(val_value)
				return nil
			}()
			return v.Value, err
		})(child)
		if err != nil {
			return out, err
		}
		if _, err := aper.CompleteOpenTypeValue(child, value); err != nil {
			return out, err
		}
		out.rowIntersystemSONConfigurationTransferECT = &value
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
func (v ENBConfigurationTransferIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ENBConfigurationTransferIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(129):
		if v.rowSONConfigurationTransferECT == nil {
			return nil, fmt.Errorf("%s missing value", "ENBConfigurationTransferIEs.id-SONConfigurationTransferECT:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowSONConfigurationTransferECT.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(294):
		if v.rowENDCSONConfigurationTransferECT == nil {
			return nil, fmt.Errorf("%s missing value", "ENBConfigurationTransferIEs.id-EN-DCSONConfigurationTransfer-ECT:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowENDCSONConfigurationTransferECT.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(310):
		if v.rowIntersystemSONConfigurationTransferECT == nil {
			return nil, fmt.Errorf("%s missing value", "ENBConfigurationTransferIEs.id-IntersystemSONConfigurationTransferECT:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.IntersystemSONConfigurationTransfer, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.IntersystemSONConfigurationTransfer
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowIntersystemSONConfigurationTransferECT, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ENBConfigurationTransferIEValue:", v.id)
	}
}

type SONConfigurationTransferExtIETable struct{}

func SONConfigurationTransferExtIEs() SONConfigurationTransferExtIETable {
	return SONConfigurationTransferExtIETable{}
}

// ID returns the ASN.1 object-set identity of SONConfigurationTransferExtIETable.
func (SONConfigurationTransferExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONConfigurationTransfer-ExtIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by SONConfigurationTransferExtIETable.
func (SONConfigurationTransferExtIETable) Table() s00.SONConfigurationTransferExtIEsValueExtensionTable {
	return func() s00.SONConfigurationTransferExtIEsValueExtensionTable {
		sealed := s00.SONConfigurationTransferExtIEsValueExtensionTable{}
		*s00.BridgeSONConfigurationTransferExtIEsValueExtensionTableFieldBound(&sealed) = true
		return sealed
	}()
}
func (SONConfigurationTransferExtIETable) infoX2TNLConfigurationInfo() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SONConfigurationTransferExtIEs().ID(), ID: s00.ProtocolExtensionID(152), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "X2TNLConfigurationInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONConfigurationTransfer-ExtIEs", Row: "id-x2TNLConfigurationInfo"}}}
}

// X2TNLConfigurationInfo returns the typed binding for the X2TNLConfigurationInfo row of SONConfigurationTransferExtIETable.
func (t SONConfigurationTransferExtIETable) X2TNLConfigurationInfo() SONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBinding {
	return SONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBinding{info: t.infoX2TNLConfigurationInfo(), codec: X2TNLConfigurationInfoValueCodec{path: "X2TNLConfigurationInfo",
		decode: func(data []byte, options aper.DecodeState) (X2TNLConfigurationInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty X2TNLConfigurationInfo
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("X2TNLConfigurationInfo")
			var zero SONConfigurationTransferExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(152), raw)
			if err != nil {
				var empty X2TNLConfigurationInfo
				return empty, runtime.WrapDecodePath(err, "X2TNLConfigurationInfo")
			}
			value, ok := decoded.AsX2TNLConfigurationInfo()
			if !ok {
				var empty X2TNLConfigurationInfo
				return empty, fmt.Errorf("binding SONConfigurationTransfer-ExtIEs.id-x2TNLConfigurationInfo: no selected value")
			}
			return *value, nil
		},
		encode: func(value X2TNLConfigurationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SONConfigurationTransferExtIEsValue{id: s00.ProtocolIEID(152), rowX2TNLConfigurationInfo: &value}).encodeFresh(fresh, budget)
		}, capture: func(v X2TNLConfigurationInfo, options aper.DecodeState) (X2TNLConfigurationInfo, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APX2TNLConfigurationInfo(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v X2TNLConfigurationInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APX2TNLConfigurationInfo(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:X2TNLConfigurationInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value X2TNLConfigurationInfo) SONConfigurationTransferExtIEsValue {
		return SONConfigurationTransferExtIEsValue{id: s00.ProtocolIEID(152), rowX2TNLConfigurationInfo: &value}
	}, get: func(value *SONConfigurationTransferExtIEsValue) (*X2TNLConfigurationInfo, bool) {
		return value.AsX2TNLConfigurationInfo()
	}}
}
func (SONConfigurationTransferExtIETable) infoSynchronisationInformation() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SONConfigurationTransferExtIEs().ID(), ID: s00.ProtocolExtensionID(209), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SynchronisationInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONConfigurationTransfer-ExtIEs", Row: "id-Synchronisation-Information"}}}
}

// SynchronisationInformation returns the typed binding for the SynchronisationInformation row of SONConfigurationTransferExtIETable.
func (t SONConfigurationTransferExtIETable) SynchronisationInformation() SONConfigurationTransferExtIEsSynchronisationInformationExtBinding {
	return SONConfigurationTransferExtIEsSynchronisationInformationExtBinding{info: t.infoSynchronisationInformation(), codec: func() s31.SynchronisationInformationValueCodec {
		sealed := s31.SynchronisationInformationValueCodec{}
		*s31.BridgeSynchronisationInformationValueCodecFieldPath(&sealed) = "SynchronisationInformation"
		*s31.BridgeSynchronisationInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.SynchronisationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.SynchronisationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SynchronisationInformation")
			var zero SONConfigurationTransferExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(209), raw)
			if err != nil {
				var empty s31.SynchronisationInformation
				return empty, runtime.WrapDecodePath(err, "SynchronisationInformation")
			}
			value, ok := decoded.AsSynchronisationInformation()
			if !ok {
				var empty s31.SynchronisationInformation
				return empty, fmt.Errorf("binding SONConfigurationTransfer-ExtIEs.id-Synchronisation-Information: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeSynchronisationInformationValueCodecFieldEncode(&sealed) = func(value s31.SynchronisationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SONConfigurationTransferExtIEsValue{id: s00.ProtocolIEID(209), rowSynchronisationInformation: &value}).encodeFresh(fresh, budget)
		}
		*s31.BridgeSynchronisationInformationValueCodecFieldCapture(&sealed) = func(v s31.SynchronisationInformation, options aper.DecodeState) (s31.SynchronisationInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s31.BridgeCaptureS1APSynchronisationInformation(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s31.BridgeSynchronisationInformationValueCodecFieldCompare(&sealed) = func(v s31.SynchronisationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APSynchronisationInformation(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeSynchronisationInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SynchronisationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.SynchronisationInformation) SONConfigurationTransferExtIEsValue {
			return SONConfigurationTransferExtIEsValue{id: s00.ProtocolIEID(209), rowSynchronisationInformation: &value}
		}, get: func(value *SONConfigurationTransferExtIEsValue) (*s31.SynchronisationInformation, bool) {
			return value.AsSynchronisationInformation()
		}}
}
func (SONConfigurationTransferExtIETable) infoRequestedTNLInfo() s00.ExtensionInfo {
	return s00.ExtensionInfo{Table: SONConfigurationTransferExtIEs().ID(), ID: s00.ProtocolExtensionID(356), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RequestedTNLInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SONConfigurationTransfer-ExtIEs", Row: "id-RequestedTNLInfo"}}}
}

// RequestedTNLInfo returns the typed binding for the RequestedTNLInfo row of SONConfigurationTransferExtIETable.
func (t SONConfigurationTransferExtIETable) RequestedTNLInfo() SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding {
	return SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding{info: t.infoRequestedTNLInfo(), codec: func() s26.RequestedTNLInfoValueCodec {
		sealed := s26.RequestedTNLInfoValueCodec{}
		*s26.BridgeRequestedTNLInfoValueCodecFieldPath(&sealed) = "RequestedTNLInfo"
		*s26.BridgeRequestedTNLInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.RequestedTNLInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s26.RequestedTNLInfo
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("RequestedTNLInfo")
			var zero SONConfigurationTransferExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(356), raw)
			if err != nil {
				var empty s26.RequestedTNLInfo
				return empty, runtime.WrapDecodePath(err, "RequestedTNLInfo")
			}
			value, ok := decoded.AsRequestedTNLInfo()
			if !ok {
				var empty s26.RequestedTNLInfo
				return empty, fmt.Errorf("binding SONConfigurationTransfer-ExtIEs.id-RequestedTNLInfo: no selected value")
			}
			return *value, nil
		}
		*s26.BridgeRequestedTNLInfoValueCodecFieldEncode(&sealed) = func(value s26.RequestedTNLInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SONConfigurationTransferExtIEsValue{id: s00.ProtocolIEID(356), rowRequestedTNLInfo: &value}).encodeFresh(fresh, budget)
		}
		*s26.BridgeRequestedTNLInfoValueCodecFieldCapture(&sealed) = func(v s26.RequestedTNLInfo, options aper.DecodeState) (s26.RequestedTNLInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s26.BridgeCaptureS1APRequestedTNLInfo(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s26.BridgeRequestedTNLInfoValueCodecFieldCompare(&sealed) = func(v s26.RequestedTNLInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s26.BridgeCompareS1APRequestedTNLInfo(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s26.BridgeRequestedTNLInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RequestedTNLInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s26.RequestedTNLInfo) SONConfigurationTransferExtIEsValue {
			return SONConfigurationTransferExtIEsValue{id: s00.ProtocolIEID(356), rowRequestedTNLInfo: &value}
		}, get: func(value *SONConfigurationTransferExtIEsValue) (*s26.RequestedTNLInfo, bool) {
			return value.AsRequestedTNLInfo()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in SONConfigurationTransferExtIETable.
func (t SONConfigurationTransferExtIETable) NewOpaque(id s00.ProtocolExtensionID, criticality s00.Criticality, data []byte) (SONConfigurationTransferExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(152):
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-x2TNLConfigurationInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(209):
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-Synchronisation-Information requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(356):
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-RequestedTNLInfo requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return SONConfigurationTransferExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: SONConfigurationTransferExtIEsValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// RequestedTNLInfoCodec binds the complete APER value type.
func RequestedTNLInfoCodec() s26.RequestedTNLInfoValueCodec {
	return SONConfigurationTransferExtIEs().RequestedTNLInfo().Codec()
}

// SONInformationCodec binds the complete source value type.
func SONInformationCodec() SONInformationValueCodec {
	return SONInformationValueCodec{path: "SONInformation", decode: func(data []byte, options aper.DecodeState) (SONInformation, error) {
		var value SONInformation
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SONInformation{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SONInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SONInformation, options aper.DecodeState) (SONInformation, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSONInformation(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v SONInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSONInformation(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONInformation"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// SONInformationReplyCodec binds the complete source value type.
func SONInformationReplyCodec() SONInformationReplyValueCodec {
	return SONInformationReplyValueCodec{path: "SONInformationReply", decode: func(data []byte, options aper.DecodeState) (SONInformationReply, error) {
		var value SONInformationReply
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SONInformationReply{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SONInformationReply, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SONInformationReply, options aper.DecodeState) (SONInformationReply, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APSONInformationReply(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v SONInformationReply, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APSONInformationReply(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SONInformationReply"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
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

// SynchronisationInformationCodec binds the complete APER value type.
func SynchronisationInformationCodec() s31.SynchronisationInformationValueCodec {
	return SONConfigurationTransferExtIEs().SynchronisationInformation().Codec()
}

// X2TNLConfigurationInfoCodec binds the complete APER value type.
func X2TNLConfigurationInfoCodec() X2TNLConfigurationInfoValueCodec {
	return SONConfigurationTransferExtIEs().X2TNLConfigurationInfo().Codec()
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
	rows := []s00.FieldInfo{s49.HandoverRequestIEs().MMEUES1APID().Info(), s49.HandoverRequestIEs().HandoverType().Info(), s49.HandoverRequestIEs().Cause().Info(), s49.HandoverRequestIEs().UEaggregateMaximumBitrate().Info(), s49.HandoverRequestIEs().ERABToBeSetupListHOReq().Info(), s49.HandoverRequestIEs().SourceToTargetTransparentContainer().Info(), s49.HandoverRequestIEs().UESecurityCapabilities().Info(), s49.HandoverRequestIEs().HandoverRestrictionList().Info(), s49.HandoverRequestIEs().TraceActivation().Info(), s49.HandoverRequestIEs().RequestType().Info(), s49.HandoverRequestIEs().SRVCCOperationPossible().Info(), s49.HandoverRequestIEs().SecurityContext().Info(), s49.HandoverRequestIEs().NASSecurityParameterstoEUTRAN().Info(), s49.HandoverRequestIEs().CSGId().Info(), s49.HandoverRequestIEs().CSGMembershipStatus().Info(), s49.HandoverRequestIEs().GUMMEIID().Info(), s49.HandoverRequestIEs().MMEUES1APID2().Info(), s49.HandoverRequestIEs().ManagementBasedMDTAllowed().Info(), s49.HandoverRequestIEs().ManagementBasedMDTPLMNList().Info(), s49.HandoverRequestIEs().MaskedIMEISV().Info(), s49.HandoverRequestIEs().ExpectedUEBehaviour().Info(), s49.HandoverRequestIEs().ProSeAuthorized().Info(), s49.HandoverRequestIEs().UEUserPlaneCIoTSupportIndicator().Info(), s49.HandoverRequestIEs().V2XServicesAuthorized().Info(), s49.HandoverRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s49.HandoverRequestIEs().EnhancedCoverageRestricted().Info(), s49.HandoverRequestIEs().NRUESecurityCapabilities().Info(), s49.HandoverRequestIEs().CEModeBRestricted().Info(), s49.HandoverRequestIEs().AerialUEsubscriptionInformation().Info(), s49.HandoverRequestIEs().PendingDataIndication().Info(), s49.HandoverRequestIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s49.HandoverRequestIEs().AdditionalRRMPriorityIndex().Info(), s49.HandoverRequestIEs().IABAuthorized().Info(), s49.HandoverRequestIEs().NRV2XServicesAuthorized().Info(), s49.HandoverRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s49.HandoverRequestIEs().PC5QoSParameters().Info(), s49.HandoverRequestIEs().UERadioCapabilityID().Info(), s49.HandoverRequestIEs().TimeRefDistribution().Info()}
	report := s49.BridgeHandoverRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverRequest.protocolIEs", budget)
	BridgeWalkValidationHandoverRequest(v, &report, "HandoverRequest", true)
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
	report := s42.BridgePathSwitchRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "PathSwitchRequest.protocolIEs", budget)
	BridgeWalkValidationPathSwitchRequest(v, &report, "PathSwitchRequest", true)
	return report, nil
}
func BridgeValidatePathSwitchRequestAcknowledgeBudget(v *s48.PathSwitchRequestAcknowledge, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil PathSwitchRequestAcknowledge")
	}
	rows := []s00.FieldInfo{s47.PathSwitchRequestAcknowledgeIEs().MMEUES1APID().Info(), s47.PathSwitchRequestAcknowledgeIEs().ENBUES1APID().Info(), s47.PathSwitchRequestAcknowledgeIEs().UEaggregateMaximumBitrate().Info(), s47.PathSwitchRequestAcknowledgeIEs().ERABToBeSwitchedULList().Info(), s47.PathSwitchRequestAcknowledgeIEs().ERABToBeReleasedList().Info(), s47.PathSwitchRequestAcknowledgeIEs().SecurityContext().Info(), s47.PathSwitchRequestAcknowledgeIEs().CriticalityDiagnostics().Info(), s47.PathSwitchRequestAcknowledgeIEs().MMEUES1APID2().Info(), s47.PathSwitchRequestAcknowledgeIEs().CSGMembershipStatus().Info(), s47.PathSwitchRequestAcknowledgeIEs().ProSeAuthorized().Info(), s47.PathSwitchRequestAcknowledgeIEs().UEUserPlaneCIoTSupportIndicator().Info(), s47.PathSwitchRequestAcknowledgeIEs().V2XServicesAuthorized().Info(), s47.PathSwitchRequestAcknowledgeIEs().UESidelinkAggregateMaximumBitrate().Info(), s47.PathSwitchRequestAcknowledgeIEs().EnhancedCoverageRestricted().Info(), s47.PathSwitchRequestAcknowledgeIEs().NRUESecurityCapabilities().Info(), s47.PathSwitchRequestAcknowledgeIEs().CEModeBRestricted().Info(), s47.PathSwitchRequestAcknowledgeIEs().AerialUEsubscriptionInformation().Info(), s47.PathSwitchRequestAcknowledgeIEs().PendingDataIndication().Info(), s47.PathSwitchRequestAcknowledgeIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s47.PathSwitchRequestAcknowledgeIEs().HandoverRestrictionList().Info(), s47.PathSwitchRequestAcknowledgeIEs().AdditionalRRMPriorityIndex().Info(), s47.PathSwitchRequestAcknowledgeIEs().NRV2XServicesAuthorized().Info(), s47.PathSwitchRequestAcknowledgeIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s47.PathSwitchRequestAcknowledgeIEs().PC5QoSParameters().Info(), s47.PathSwitchRequestAcknowledgeIEs().UERadioCapabilityID().Info(), s47.PathSwitchRequestAcknowledgeIEs().UESecurityCapabilities().Info(), s47.PathSwitchRequestAcknowledgeIEs().ERABToBeUpdatedList().Info(), s47.PathSwitchRequestAcknowledgeIEs().TimeRefDistribution().Info()}
	report := s48.BridgePathSwitchRequestAcknowledgeIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "PathSwitchRequestAcknowledge.protocolIEs", budget)
	BridgeWalkValidationPathSwitchRequestAcknowledge(v, &report, "PathSwitchRequestAcknowledge", true)
	return report, nil
}
func BridgeValidateERABSetupResponseBudget(v *s47.ERABSetupResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABSetupResponse")
	}
	rows := []s00.FieldInfo{s46.ERABSetupResponseIEs().MMEUES1APID().Info(), s46.ERABSetupResponseIEs().ENBUES1APID().Info(), s46.ERABSetupResponseIEs().ERABSetupListBearerSURes().Info(), s46.ERABSetupResponseIEs().ERABFailedToSetupListBearerSURes().Info(), s46.ERABSetupResponseIEs().CriticalityDiagnostics().Info(), s46.ERABSetupResponseIEs().UserLocationInformation().Info()}
	report := s47.BridgeERABSetupResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABSetupResponse.protocolIEs", budget)
	BridgeWalkValidationERABSetupResponse(v, &report, "ERABSetupResponse", true)
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
	rows := []s00.FieldInfo{s46.ERABModifyResponseIEs().MMEUES1APID().Info(), s46.ERABModifyResponseIEs().ENBUES1APID().Info(), s46.ERABModifyResponseIEs().ERABModifyListBearerModRes().Info(), s46.ERABModifyResponseIEs().ERABFailedToModifyList().Info(), s46.ERABModifyResponseIEs().CriticalityDiagnostics().Info(), s46.ERABModifyResponseIEs().SecondaryRATDataUsageReportList().Info(), s46.ERABModifyResponseIEs().UserLocationInformation().Info()}
	report := s46.BridgeERABModifyResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABModifyResponse.protocolIEs", budget)
	BridgeWalkValidationERABModifyResponse(v, &report, "ERABModifyResponse", true)
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
	rows := []s00.FieldInfo{s46.ERABReleaseResponseIEs().MMEUES1APID().Info(), s46.ERABReleaseResponseIEs().ENBUES1APID().Info(), s46.ERABReleaseResponseIEs().ERABReleaseListBearerRelComp().Info(), s46.ERABReleaseResponseIEs().ERABFailedToReleaseList().Info(), s46.ERABReleaseResponseIEs().CriticalityDiagnostics().Info(), s46.ERABReleaseResponseIEs().UserLocationInformation().Info(), s46.ERABReleaseResponseIEs().SecondaryRATDataUsageReportList().Info()}
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
	rows := []s00.FieldInfo{s46.ERABReleaseIndicationIEs().MMEUES1APID().Info(), s46.ERABReleaseIndicationIEs().ENBUES1APID().Info(), s46.ERABReleaseIndicationIEs().ERABReleasedList().Info(), s46.ERABReleaseIndicationIEs().UserLocationInformation().Info(), s46.ERABReleaseIndicationIEs().SecondaryRATDataUsageReportList().Info()}
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
	rows := []s00.FieldInfo{s49.InitialContextSetupRequestIEs().MMEUES1APID().Info(), s49.InitialContextSetupRequestIEs().ENBUES1APID().Info(), s49.InitialContextSetupRequestIEs().UEaggregateMaximumBitrate().Info(), s49.InitialContextSetupRequestIEs().ERABToBeSetupListCtxtSUReq().Info(), s49.InitialContextSetupRequestIEs().UESecurityCapabilities().Info(), s49.InitialContextSetupRequestIEs().SecurityKey().Info(), s49.InitialContextSetupRequestIEs().TraceActivation().Info(), s49.InitialContextSetupRequestIEs().HandoverRestrictionList().Info(), s49.InitialContextSetupRequestIEs().UERadioCapability().Info(), s49.InitialContextSetupRequestIEs().SubscriberProfileIDforRFP().Info(), s49.InitialContextSetupRequestIEs().CSFallbackIndicator().Info(), s49.InitialContextSetupRequestIEs().SRVCCOperationPossible().Info(), s49.InitialContextSetupRequestIEs().CSGMembershipStatus().Info(), s49.InitialContextSetupRequestIEs().RegisteredLAI().Info(), s49.InitialContextSetupRequestIEs().GUMMEIID().Info(), s49.InitialContextSetupRequestIEs().MMEUES1APID2().Info(), s49.InitialContextSetupRequestIEs().ManagementBasedMDTAllowed().Info(), s49.InitialContextSetupRequestIEs().ManagementBasedMDTPLMNList().Info(), s49.InitialContextSetupRequestIEs().AdditionalCSFallbackIndicator().Info(), s49.InitialContextSetupRequestIEs().MaskedIMEISV().Info(), s49.InitialContextSetupRequestIEs().ExpectedUEBehaviour().Info(), s49.InitialContextSetupRequestIEs().ProSeAuthorized().Info(), s49.InitialContextSetupRequestIEs().UEUserPlaneCIoTSupportIndicator().Info(), s49.InitialContextSetupRequestIEs().V2XServicesAuthorized().Info(), s49.InitialContextSetupRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s49.InitialContextSetupRequestIEs().EnhancedCoverageRestricted().Info(), s49.InitialContextSetupRequestIEs().NRUESecurityCapabilities().Info(), s49.InitialContextSetupRequestIEs().CEModeBRestricted().Info(), s49.InitialContextSetupRequestIEs().AerialUEsubscriptionInformation().Info(), s49.InitialContextSetupRequestIEs().PendingDataIndication().Info(), s49.InitialContextSetupRequestIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s49.InitialContextSetupRequestIEs().AdditionalRRMPriorityIndex().Info(), s49.InitialContextSetupRequestIEs().IABAuthorized().Info(), s49.InitialContextSetupRequestIEs().NRV2XServicesAuthorized().Info(), s49.InitialContextSetupRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s49.InitialContextSetupRequestIEs().PC5QoSParameters().Info(), s49.InitialContextSetupRequestIEs().UERadioCapabilityID().Info(), s49.InitialContextSetupRequestIEs().CoarseUELocation().Info(), s49.InitialContextSetupRequestIEs().TimeRefDistribution().Info()}
	report := s49.BridgeInitialContextSetupRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "InitialContextSetupRequest.protocolIEs", budget)
	BridgeWalkValidationInitialContextSetupRequest(v, &report, "InitialContextSetupRequest", true)
	return report, nil
}
func BridgeValidatePagingBudget(v *s50.Paging, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil Paging")
	}
	rows := []s00.FieldInfo{s50.PagingIEs().UEIdentityIndexValue().Info(), s50.PagingIEs().UEPagingID().Info(), s50.PagingIEs().PagingDRX().Info(), s50.PagingIEs().CNDomain().Info(), s50.PagingIEs().TAIList().Info(), s50.PagingIEs().CSGIdList().Info(), s50.PagingIEs().PagingPriority().Info(), s50.PagingIEs().UERadioCapabilityForPaging().Info(), s50.PagingIEs().AssistanceDataForPaging().Info(), s50.PagingIEs().PagingEDRXInformation().Info(), s50.PagingIEs().ExtendedUEIdentityIndexValue().Info(), s50.PagingIEs().NBIoTPagingEDRXInformation().Info(), s50.PagingIEs().NBIoTUEIdentityIndexValue().Info(), s50.PagingIEs().EnhancedCoverageRestricted().Info(), s50.PagingIEs().CEModeBRestricted().Info(), s50.PagingIEs().DataSize().Info(), s50.PagingIEs().WUSAssistanceInformation().Info(), s50.PagingIEs().NBIoTPagingDRX().Info(), s50.PagingIEs().PagingCause().Info()}
	report := s50.BridgePagingIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "Paging.protocolIEs", budget)
	BridgeWalkValidationPaging(v, &report, "Paging", true)
	return report, nil
}
func BridgeValidateUplinkNASTransportBudget(v *s45.UplinkNASTransport, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UplinkNASTransport")
	}
	rows := []s00.FieldInfo{s32.UplinkNASTransportIEs().MMEUES1APID().Info(), s32.UplinkNASTransportIEs().ENBUES1APID().Info(), s32.UplinkNASTransportIEs().NASPDU().Info(), s32.UplinkNASTransportIEs().EUTRANCGI().Info(), s32.UplinkNASTransportIEs().TAI().Info(), s32.UplinkNASTransportIEs().GWTransportLayerAddress().Info(), s32.UplinkNASTransportIEs().SIPTOLGWTransportLayerAddress().Info(), s32.UplinkNASTransportIEs().LHNID().Info(), s32.UplinkNASTransportIEs().PSCellInformation().Info(), s32.UplinkNASTransportIEs().LTENTNTAIInformation().Info()}
	report := s45.BridgeUplinkNASTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UplinkNASTransport.protocolIEs", budget)
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
func BridgeValidateResetAcknowledgeBudget(v *s45.ResetAcknowledge, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ResetAcknowledge")
	}
	rows := []s00.FieldInfo{s45.ResetAcknowledgeIEs().UEAssociatedLogicalS1ConnectionListResAck().Info(), s45.ResetAcknowledgeIEs().CriticalityDiagnostics().Info()}
	report := s45.BridgeResetAcknowledgeIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ResetAcknowledge.protocolIEs", budget)
	BridgeWalkValidationResetAcknowledge(v, &report, "ResetAcknowledge", true)
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
func BridgeValidateUplinkS1cdma2000tunnellingBudget(v *s45.UplinkS1cdma2000tunnelling, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UplinkS1cdma2000tunnelling")
	}
	rows := []s00.FieldInfo{s21.UplinkS1cdma2000tunnellingIEs().MMEUES1APID().Info(), s21.UplinkS1cdma2000tunnellingIEs().ENBUES1APID().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000RATType().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000SectorID().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000HORequiredIndication().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000OneXSRVCCInfo().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000OneXRAND().Info(), s21.UplinkS1cdma2000tunnellingIEs().Cdma2000PDU().Info(), s21.UplinkS1cdma2000tunnellingIEs().EUTRANRoundTripDelayEstimationInfo().Info()}
	report := s45.BridgeUplinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UplinkS1cdma2000tunnelling.protocolIEs", budget)
	BridgeWalkValidationUplinkS1cdma2000tunnelling(v, &report, "UplinkS1cdma2000tunnelling", true)
	return report, nil
}
func BridgeValidateUEContextModificationRequestBudget(v *s48.UEContextModificationRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextModificationRequest")
	}
	rows := []s00.FieldInfo{s47.UEContextModificationRequestIEs().MMEUES1APID().Info(), s47.UEContextModificationRequestIEs().ENBUES1APID().Info(), s47.UEContextModificationRequestIEs().SecurityKey().Info(), s47.UEContextModificationRequestIEs().SubscriberProfileIDforRFP().Info(), s47.UEContextModificationRequestIEs().UEaggregateMaximumBitrate().Info(), s47.UEContextModificationRequestIEs().CSFallbackIndicator().Info(), s47.UEContextModificationRequestIEs().UESecurityCapabilities().Info(), s47.UEContextModificationRequestIEs().CSGMembershipStatus().Info(), s47.UEContextModificationRequestIEs().RegisteredLAI().Info(), s47.UEContextModificationRequestIEs().AdditionalCSFallbackIndicator().Info(), s47.UEContextModificationRequestIEs().ProSeAuthorized().Info(), s47.UEContextModificationRequestIEs().SRVCCOperationPossible().Info(), s47.UEContextModificationRequestIEs().SRVCCOperationNotPossible().Info(), s47.UEContextModificationRequestIEs().V2XServicesAuthorized().Info(), s47.UEContextModificationRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s47.UEContextModificationRequestIEs().NRUESecurityCapabilities().Info(), s47.UEContextModificationRequestIEs().AerialUEsubscriptionInformation().Info(), s47.UEContextModificationRequestIEs().AdditionalRRMPriorityIndex().Info(), s47.UEContextModificationRequestIEs().IABAuthorized().Info(), s47.UEContextModificationRequestIEs().NRV2XServicesAuthorized().Info(), s47.UEContextModificationRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s47.UEContextModificationRequestIEs().PC5QoSParameters().Info(), s47.UEContextModificationRequestIEs().UERadioCapabilityID().Info(), s47.UEContextModificationRequestIEs().TimeRefDistribution().Info()}
	report := s48.BridgeUEContextModificationRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextModificationRequest.protocolIEs", budget)
	BridgeWalkValidationUEContextModificationRequest(v, &report, "UEContextModificationRequest", true)
	return report, nil
}
func BridgeValidateUEContextModificationResponseBudget(v *s37.UEContextModificationResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextModificationResponse")
	}
	rows := []s00.FieldInfo{s24.UEContextModificationResponseIEs().MMEUES1APID().Info(), s24.UEContextModificationResponseIEs().ENBUES1APID().Info(), s24.UEContextModificationResponseIEs().CriticalityDiagnostics().Info()}
	report := s37.BridgeUEContextModificationResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextModificationResponse.protocolIEs", budget)
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
	report := s37.BridgeUEContextModificationFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextModificationFailure.protocolIEs", budget)
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
func BridgeValidateUEContextReleaseCompleteBudget(v *s47.UEContextReleaseComplete, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextReleaseComplete")
	}
	rows := []s00.FieldInfo{s46.UEContextReleaseCompleteIEs().MMEUES1APID().Info(), s46.UEContextReleaseCompleteIEs().ENBUES1APID().Info(), s46.UEContextReleaseCompleteIEs().CriticalityDiagnostics().Info(), s46.UEContextReleaseCompleteIEs().UserLocationInformation().Info(), s46.UEContextReleaseCompleteIEs().InformationOnRecommendedCellsAndENBsForPaging().Info(), s46.UEContextReleaseCompleteIEs().CellIdentifierAndCELevelForCECapableUEs().Info(), s46.UEContextReleaseCompleteIEs().SecondaryRATDataUsageReportList().Info(), s46.UEContextReleaseCompleteIEs().TimeSinceSecondaryNodeRelease().Info()}
	report := s47.BridgeUEContextReleaseCompleteIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextReleaseComplete.protocolIEs", budget)
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
	rows := []s00.FieldInfo{s33.WriteReplaceWarningResponseIEs().MessageIdentifier().Info(), s33.WriteReplaceWarningResponseIEs().SerialNumber().Info(), s33.WriteReplaceWarningResponseIEs().BroadcastCompletedAreaList().Info(), s33.WriteReplaceWarningResponseIEs().CriticalityDiagnostics().Info()}
	report := BridgeWriteReplaceWarningResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "WriteReplaceWarningResponse.protocolIEs", budget)
	BridgeWalkValidationWriteReplaceWarningResponse(v, &report, "WriteReplaceWarningResponse", true)
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
func BridgeValidateUplinkUEAssociatedLPPaTransportBudget(v *s45.UplinkUEAssociatedLPPaTransport, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UplinkUEAssociatedLPPaTransport")
	}
	rows := []s00.FieldInfo{s12.UplinkUEAssociatedLPPaTransportIEs().MMEUES1APID().Info(), s12.UplinkUEAssociatedLPPaTransportIEs().ENBUES1APID().Info(), s12.UplinkUEAssociatedLPPaTransportIEs().RoutingID().Info(), s12.UplinkUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
	report := s45.BridgeUplinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UplinkUEAssociatedLPPaTransport.protocolIEs", budget)
	BridgeWalkValidationUplinkUEAssociatedLPPaTransport(v, &report, "UplinkUEAssociatedLPPaTransport", true)
	return report, nil
}
func BridgeValidateUplinkNonUEAssociatedLPPaTransportBudget(v *s45.UplinkNonUEAssociatedLPPaTransport, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UplinkNonUEAssociatedLPPaTransport")
	}
	rows := []s00.FieldInfo{s12.UplinkNonUEAssociatedLPPaTransportIEs().RoutingID().Info(), s12.UplinkNonUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
	report := s45.BridgeUplinkNonUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UplinkNonUEAssociatedLPPaTransport.protocolIEs", budget)
	BridgeWalkValidationUplinkNonUEAssociatedLPPaTransport(v, &report, "UplinkNonUEAssociatedLPPaTransport", true)
	return report, nil
}
func BridgeValidateUERadioCapabilityMatchRequestBudget(v *s37.UERadioCapabilityMatchRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UERadioCapabilityMatchRequest")
	}
	rows := []s00.FieldInfo{s12.UERadioCapabilityMatchRequestIEs().MMEUES1APID().Info(), s12.UERadioCapabilityMatchRequestIEs().ENBUES1APID().Info(), s12.UERadioCapabilityMatchRequestIEs().UERadioCapability().Info(), s12.UERadioCapabilityMatchRequestIEs().UERadioCapabilityID().Info()}
	report := s37.BridgeUERadioCapabilityMatchRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UERadioCapabilityMatchRequest.protocolIEs", budget)
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
func BridgeValidateERABModificationIndicationBudget(v *s46.ERABModificationIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABModificationIndication")
	}
	rows := []s00.FieldInfo{s46.ERABModificationIndicationIEs().MMEUES1APID().Info(), s46.ERABModificationIndicationIEs().ENBUES1APID().Info(), s46.ERABModificationIndicationIEs().ERABToBeModifiedListBearerModInd().Info(), s46.ERABModificationIndicationIEs().ERABNotToBeModifiedListBearerModInd().Info(), s46.ERABModificationIndicationIEs().CSGMembershipInfo().Info(), s46.ERABModificationIndicationIEs().TunnelInformationForBBF().Info(), s46.ERABModificationIndicationIEs().SecondaryRATDataUsageReportList().Info(), s46.ERABModificationIndicationIEs().UserLocationInformation().Info()}
	report := s46.BridgeERABModificationIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABModificationIndication.protocolIEs", budget)
	BridgeWalkValidationERABModificationIndication(v, &report, "ERABModificationIndication", true)
	return report, nil
}
func BridgeValidateUEContextModificationIndicationBudget(v *s37.UEContextModificationIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextModificationIndication")
	}
	rows := []s00.FieldInfo{s21.UEContextModificationIndicationIEs().MMEUES1APID().Info(), s21.UEContextModificationIndicationIEs().ENBUES1APID().Info(), s21.UEContextModificationIndicationIEs().CSGMembershipInfo().Info()}
	report := s37.BridgeUEContextModificationIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextModificationIndication.protocolIEs", budget)
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
func BridgeValidateUEContextSuspendRequestBudget(v *s47.UEContextSuspendRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextSuspendRequest")
	}
	rows := []s00.FieldInfo{s46.UEContextSuspendRequestIEs().MMEUES1APID().Info(), s46.UEContextSuspendRequestIEs().ENBUES1APID().Info(), s46.UEContextSuspendRequestIEs().InformationOnRecommendedCellsAndENBsForPaging().Info(), s46.UEContextSuspendRequestIEs().CellIdentifierAndCELevelForCECapableUEs().Info(), s46.UEContextSuspendRequestIEs().SecondaryRATDataUsageReportList().Info(), s46.UEContextSuspendRequestIEs().UserLocationInformation().Info(), s46.UEContextSuspendRequestIEs().TimeSinceSecondaryNodeRelease().Info()}
	report := s47.BridgeUEContextSuspendRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextSuspendRequest.protocolIEs", budget)
	BridgeWalkValidationUEContextSuspendRequest(v, &report, "UEContextSuspendRequest", true)
	return report, nil
}
func BridgeValidateUEContextSuspendResponseBudget(v *s37.UEContextSuspendResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextSuspendResponse")
	}
	rows := []s00.FieldInfo{s29.UEContextSuspendResponseIEs().MMEUES1APID().Info(), s29.UEContextSuspendResponseIEs().ENBUES1APID().Info(), s29.UEContextSuspendResponseIEs().CriticalityDiagnostics().Info(), s29.UEContextSuspendResponseIEs().SecurityContext().Info()}
	report := s37.BridgeUEContextSuspendResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextSuspendResponse.protocolIEs", budget)
	BridgeWalkValidationUEContextSuspendResponse(v, &report, "UEContextSuspendResponse", true)
	return report, nil
}
func BridgeValidateUEContextResumeRequestBudget(v *s39.UEContextResumeRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextResumeRequest")
	}
	rows := []s00.FieldInfo{s39.UEContextResumeRequestIEs().MMEUES1APID().Info(), s39.UEContextResumeRequestIEs().ENBUES1APID().Info(), s39.UEContextResumeRequestIEs().ERABFailedToResumeListResumeReq().Info(), s39.UEContextResumeRequestIEs().RRCResumeCause().Info()}
	report := s39.BridgeUEContextResumeRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextResumeRequest.protocolIEs", budget)
	BridgeWalkValidationUEContextResumeRequest(v, &report, "UEContextResumeRequest", true)
	return report, nil
}
func BridgeValidateUEContextResumeResponseBudget(v *s39.UEContextResumeResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextResumeResponse")
	}
	rows := []s00.FieldInfo{s39.UEContextResumeResponseIEs().MMEUES1APID().Info(), s39.UEContextResumeResponseIEs().ENBUES1APID().Info(), s39.UEContextResumeResponseIEs().ERABFailedToResumeListResumeRes().Info(), s39.UEContextResumeResponseIEs().CriticalityDiagnostics().Info(), s39.UEContextResumeResponseIEs().SecurityContext().Info(), s39.UEContextResumeResponseIEs().PendingDataIndication().Info()}
	report := s39.BridgeUEContextResumeResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextResumeResponse.protocolIEs", budget)
	BridgeWalkValidationUEContextResumeResponse(v, &report, "UEContextResumeResponse", true)
	return report, nil
}
func BridgeValidateUEContextResumeFailureBudget(v *s37.UEContextResumeFailure, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextResumeFailure")
	}
	rows := []s00.FieldInfo{s24.UEContextResumeFailureIEs().MMEUES1APID().Info(), s24.UEContextResumeFailureIEs().ENBUES1APID().Info(), s24.UEContextResumeFailureIEs().Cause().Info(), s24.UEContextResumeFailureIEs().CriticalityDiagnostics().Info()}
	report := s37.BridgeUEContextResumeFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextResumeFailure.protocolIEs", budget)
	BridgeWalkValidationUEContextResumeFailure(v, &report, "UEContextResumeFailure", true)
	return report, nil
}
func BridgeValidateUEInformationTransferBudget(v *s37.UEInformationTransfer, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEInformationTransfer")
	}
	rows := []s00.FieldInfo{s31.UEInformationTransferIEs().STMSI().Info(), s31.UEInformationTransferIEs().UELevelQoSParameters().Info(), s31.UEInformationTransferIEs().UERadioCapability().Info(), s31.UEInformationTransferIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s31.UEInformationTransferIEs().PendingDataIndication().Info(), s31.UEInformationTransferIEs().MaskedIMEISV().Info()}
	report := s37.BridgeUEInformationTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEInformationTransfer.protocolIEs", budget)
	BridgeWalkValidationUEInformationTransfer(v, &report, "UEInformationTransfer", true)
	return report, nil
}
func BridgeValidateENBCPRelocationIndicationBudget(v *s38.ENBCPRelocationIndication, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBCPRelocationIndication")
	}
	rows := []s00.FieldInfo{s38.ENBCPRelocationIndicationIEs().ENBUES1APID().Info(), s38.ENBCPRelocationIndicationIEs().STMSI().Info(), s38.ENBCPRelocationIndicationIEs().EUTRANCGI().Info(), s38.ENBCPRelocationIndicationIEs().TAI().Info(), s38.ENBCPRelocationIndicationIEs().ULCPSecurityInformation().Info(), s38.ENBCPRelocationIndicationIEs().LTENTNTAIInformation().Info()}
	report := s38.BridgeENBCPRelocationIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBCPRelocationIndication.protocolIEs", budget)
	BridgeWalkValidationENBCPRelocationIndication(v, &report, "ENBCPRelocationIndication", true)
	return report, nil
}
func BridgeValidateSecondaryRATDataUsageReportBudget(v *s47.SecondaryRATDataUsageReport, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil SecondaryRATDataUsageReport")
	}
	rows := []s00.FieldInfo{s46.SecondaryRATDataUsageReportIEs().MMEUES1APID().Info(), s46.SecondaryRATDataUsageReportIEs().ENBUES1APID().Info(), s46.SecondaryRATDataUsageReportIEs().SecondaryRATDataUsageReportList().Info(), s46.SecondaryRATDataUsageReportIEs().HandoverFlag().Info(), s46.SecondaryRATDataUsageReportIEs().UserLocationInformation().Info(), s46.SecondaryRATDataUsageReportIEs().TimeSinceSecondaryNodeRelease().Info()}
	report := s47.BridgeSecondaryRATDataUsageReportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "SecondaryRATDataUsageReport.protocolIEs", budget)
	BridgeWalkValidationSecondaryRATDataUsageReport(v, &report, "SecondaryRATDataUsageReport", true)
	return report, nil
}
func BridgeValidateUERadioCapabilityIDMappingRequestBudget(v *s37.UERadioCapabilityIDMappingRequest, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UERadioCapabilityIDMappingRequest")
	}
	rows := []s00.FieldInfo{s12.UERadioCapabilityIDMappingRequestIEs().UERadioCapabilityID().Info()}
	report := s37.BridgeUERadioCapabilityIDMappingRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UERadioCapabilityIDMappingRequest.protocolIEs", budget)
	BridgeWalkValidationUERadioCapabilityIDMappingRequest(v, &report, "UERadioCapabilityIDMappingRequest", true)
	return report, nil
}
func BridgeValidateUERadioCapabilityIDMappingResponseBudget(v *s37.UERadioCapabilityIDMappingResponse, budget *aper.DecodeBudget,

) (s21.ValidationReport, error) {
	if v == nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UERadioCapabilityIDMappingResponse")
	}
	rows := []s00.FieldInfo{s24.UERadioCapabilityIDMappingResponseIEs().UERadioCapabilityID().Info(), s24.UERadioCapabilityIDMappingResponseIEs().UERadioCapability().Info(), s24.UERadioCapabilityIDMappingResponseIEs().CriticalityDiagnostics().Info()}
	report := s37.BridgeUERadioCapabilityIDMappingResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UERadioCapabilityIDMappingResponse.protocolIEs", budget)
	BridgeWalkValidationUERadioCapabilityIDMappingResponse(v, &report, "UERadioCapabilityIDMappingResponse", true)
	return report, nil
}
func ValidateHandoverRequest(v *s49.HandoverRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "HandoverRequest")
	}
	report, err := BridgeValidateHandoverRequestBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s49.BridgeHandoverRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverRequest")
}
func ValidatePathSwitchRequest(v *s41.PathSwitchRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "PathSwitchRequest")
	}
	report, err := BridgeValidatePathSwitchRequestBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s41.BridgePathSwitchRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PathSwitchRequest")
}
func ValidatePathSwitchRequestAcknowledge(v *s48.PathSwitchRequestAcknowledge, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	report, err := BridgeValidatePathSwitchRequestAcknowledgeBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s48.BridgePathSwitchRequestAcknowledgeMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PathSwitchRequestAcknowledge")
}
func ValidateERABSetupResponse(v *s47.ERABSetupResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABSetupResponse")
	}
	report, err := BridgeValidateERABSetupResponseBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s47.BridgeERABSetupResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABSetupResponse")
}
func ValidateERABModifyResponse(v *s46.ERABModifyResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABModifyResponse")
	}
	report, err := BridgeValidateERABModifyResponseBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeERABModifyResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABModifyResponse")
}
func ValidateERABReleaseResponse(v *s46.ERABReleaseResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABReleaseResponse")
	}
	report, err := BridgeValidateERABReleaseResponseBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
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
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
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
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s49.BridgeInitialContextSetupRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "InitialContextSetupRequest")
}
func ValidatePaging(v *s50.Paging, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "Paging")
	}
	report, err := BridgeValidatePagingBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s50.BridgePagingMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "Paging")
}
func ValidateUplinkNASTransport(v *s45.UplinkNASTransport, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UplinkNASTransport")
	}
	report, err := BridgeValidateUplinkNASTransportBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s45.BridgeUplinkNASTransportMethodMarshalAPERBudget(v, budget, false)
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
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeResetMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "Reset")
}
func ValidateResetAcknowledge(v *s45.ResetAcknowledge, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ResetAcknowledge")
	}
	report, err := BridgeValidateResetAcknowledgeBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s45.BridgeResetAcknowledgeMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ResetAcknowledge")
}
func ValidateUEContextReleaseRequest(v *s43.UEContextReleaseRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextReleaseRequest")
	}
	report, err := BridgeValidateUEContextReleaseRequestBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s43.BridgeUEContextReleaseRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextReleaseRequest")
}
func ValidateUplinkS1cdma2000tunnelling(v *s45.UplinkS1cdma2000tunnelling, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	report, err := BridgeValidateUplinkS1cdma2000tunnellingBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s45.BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
}
func ValidateUEContextModificationRequest(v *s48.UEContextModificationRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextModificationRequest")
	}
	report, err := BridgeValidateUEContextModificationRequestBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s48.BridgeUEContextModificationRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextModificationRequest")
}
func ValidateUEContextModificationResponse(v *s37.UEContextModificationResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextModificationResponse")
	}
	report, err := BridgeValidateUEContextModificationResponseBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s37.BridgeUEContextModificationResponseMethodMarshalAPERBudget(v, budget, false)
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
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
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
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
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
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s37.BridgeUEContextReleaseCommandMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextReleaseCommand")
}
func ValidateUEContextReleaseComplete(v *s47.UEContextReleaseComplete, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextReleaseComplete")
	}
	report, err := BridgeValidateUEContextReleaseCompleteBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s47.BridgeUEContextReleaseCompleteMethodMarshalAPERBudget(v, budget, false)
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
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s49.BridgeTraceStartMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "TraceStart")
}
func ValidateWriteReplaceWarningRequest(v *WriteReplaceWarningRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "WriteReplaceWarningRequest")
	}
	report, err := BridgeValidateWriteReplaceWarningRequestBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
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
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = v.marshalAPERBudget(budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "WriteReplaceWarningResponse")
}
func ValidateKillRequest(v *s33.KillRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "KillRequest")
	}
	report, err := BridgeValidateKillRequestBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s33.BridgeKillRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "KillRequest")
}
func ValidateUplinkUEAssociatedLPPaTransport(v *s45.UplinkUEAssociatedLPPaTransport, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	report, err := BridgeValidateUplinkUEAssociatedLPPaTransportBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s45.BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
}
func ValidateUplinkNonUEAssociatedLPPaTransport(v *s45.UplinkNonUEAssociatedLPPaTransport, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	report, err := BridgeValidateUplinkNonUEAssociatedLPPaTransportBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s45.BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
}
func ValidateUERadioCapabilityMatchRequest(v *s37.UERadioCapabilityMatchRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UERadioCapabilityMatchRequest")
	}
	report, err := BridgeValidateUERadioCapabilityMatchRequestBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s37.BridgeUERadioCapabilityMatchRequestMethodMarshalAPERBudget(v, budget, false)
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
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s37.BridgeUERadioCapabilityMatchResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UERadioCapabilityMatchResponse")
}
func ValidateERABModificationIndication(v *s46.ERABModificationIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ERABModificationIndication")
	}
	report, err := BridgeValidateERABModificationIndicationBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeERABModificationIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABModificationIndication")
}
func ValidateUEContextModificationIndication(v *s37.UEContextModificationIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextModificationIndication")
	}
	report, err := BridgeValidateUEContextModificationIndicationBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s37.BridgeUEContextModificationIndicationMethodMarshalAPERBudget(v, budget, false)
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
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeUEContextModificationConfirmMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextModificationConfirm")
}
func ValidateUEContextSuspendRequest(v *s47.UEContextSuspendRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextSuspendRequest")
	}
	report, err := BridgeValidateUEContextSuspendRequestBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s47.BridgeUEContextSuspendRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextSuspendRequest")
}
func ValidateUEContextSuspendResponse(v *s37.UEContextSuspendResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextSuspendResponse")
	}
	report, err := BridgeValidateUEContextSuspendResponseBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s37.BridgeUEContextSuspendResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextSuspendResponse")
}
func ValidateUEContextResumeRequest(v *s39.UEContextResumeRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextResumeRequest")
	}
	report, err := BridgeValidateUEContextResumeRequestBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s39.BridgeUEContextResumeRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextResumeRequest")
}
func ValidateUEContextResumeResponse(v *s39.UEContextResumeResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextResumeResponse")
	}
	report, err := BridgeValidateUEContextResumeResponseBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s39.BridgeUEContextResumeResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextResumeResponse")
}
func ValidateUEContextResumeFailure(v *s37.UEContextResumeFailure, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEContextResumeFailure")
	}
	report, err := BridgeValidateUEContextResumeFailureBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s37.BridgeUEContextResumeFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextResumeFailure")
}
func ValidateUEInformationTransfer(v *s37.UEInformationTransfer, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UEInformationTransfer")
	}
	report, err := BridgeValidateUEInformationTransferBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s37.BridgeUEInformationTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEInformationTransfer")
}
func ValidateENBCPRelocationIndication(v *s38.ENBCPRelocationIndication, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	report, err := BridgeValidateENBCPRelocationIndicationBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s38.BridgeENBCPRelocationIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBCPRelocationIndication")
}
func ValidateSecondaryRATDataUsageReport(v *s47.SecondaryRATDataUsageReport, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	report, err := BridgeValidateSecondaryRATDataUsageReportBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s47.BridgeSecondaryRATDataUsageReportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "SecondaryRATDataUsageReport")
}
func ValidateUERadioCapabilityIDMappingRequest(v *s37.UERadioCapabilityIDMappingRequest, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	report, err := BridgeValidateUERadioCapabilityIDMappingRequestBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s37.BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
}
func ValidateUERadioCapabilityIDMappingResponse(v *s37.UERadioCapabilityIDMappingResponse, options ...aper.ValidationOption) (s21.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s21.ValidationReport{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	report, err := BridgeValidateUERadioCapabilityIDMappingResponseBudget(v, budget)
	if err == nil && !s48.BridgeValidationHasValueMismatch(report) {
		_, err = s37.BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		err = *s21.BridgeValidationReportFieldErr(&report)
	}
	*s21.BridgeValidationReportFieldBudget(&report) = nil
	*s21.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
}
func BridgeWalkValidationENBCPRelocationIndication(v *s38.ENBCPRelocationIndication, report *s21.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s38.ENBCPRelocationIndicationIEs().ENBUES1APID().Info(), s38.ENBCPRelocationIndicationIEs().STMSI().Info(), s38.ENBCPRelocationIndicationIEs().EUTRANCGI().Info(), s38.ENBCPRelocationIndicationIEs().TAI().Info(), s38.ENBCPRelocationIndicationIEs().ULCPSecurityInformation().Info(), s38.ENBCPRelocationIndicationIEs().LTENTNTAIInformation().Info()}
			s26.BridgeMergeNestedValidation(report, s38.BridgeENBCPRelocationIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(96):
				if value, ok := fields[i].Value.AsSTMSI(); ok {
					s50.BridgeWalkValidationSTMSI(value, report, fmt.Sprintf("%s[%d]{id=96}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					s50.BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					s50.BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(254):
				if value, ok := fields[i].Value.AsULCPSecurityInformation(); ok {
					BridgeWalkValidationULCPSecurityInformation(value, report, fmt.Sprintf("%s[%d]{id=254}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					s50.BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
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
			rows := []s00.FieldInfo{s46.ERABModificationIndicationIEs().MMEUES1APID().Info(), s46.ERABModificationIndicationIEs().ENBUES1APID().Info(), s46.ERABModificationIndicationIEs().ERABToBeModifiedListBearerModInd().Info(), s46.ERABModificationIndicationIEs().ERABNotToBeModifiedListBearerModInd().Info(), s46.ERABModificationIndicationIEs().CSGMembershipInfo().Info(), s46.ERABModificationIndicationIEs().TunnelInformationForBBF().Info(), s46.ERABModificationIndicationIEs().SecondaryRATDataUsageReportList().Info(), s46.ERABModificationIndicationIEs().UserLocationInformation().Info()}
			s26.BridgeMergeNestedValidation(report, s46.BridgeERABModificationIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(199):
				if value, ok := fields[i].Value.AsERABToBeModifiedListBearerModInd(); ok {
					s50.BridgeWalkValidationERABToBeModifiedListBearerModInd(value, report, fmt.Sprintf("%s[%d]{id=199}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(201):
				if value, ok := fields[i].Value.AsERABNotToBeModifiedListBearerModInd(); ok {
					s50.BridgeWalkValidationERABNotToBeModifiedListBearerModInd(value, report, fmt.Sprintf("%s[%d]{id=201}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(226):
				if value, ok := fields[i].Value.AsCSGMembershipInfo(); ok {
					s50.BridgeWalkValidationCSGMembershipInfo(value, report, fmt.Sprintf("%s[%d]{id=226}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(176):
				if value, ok := fields[i].Value.AsTunnelInformationForBBF(); ok {
					s50.BridgeWalkValidationTunnelInformation(value, report, fmt.Sprintf("%s[%d]{id=176}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s50.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
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
			rows := []s00.FieldInfo{s46.ERABModifyResponseIEs().MMEUES1APID().Info(), s46.ERABModifyResponseIEs().ENBUES1APID().Info(), s46.ERABModifyResponseIEs().ERABModifyListBearerModRes().Info(), s46.ERABModifyResponseIEs().ERABFailedToModifyList().Info(), s46.ERABModifyResponseIEs().CriticalityDiagnostics().Info(), s46.ERABModifyResponseIEs().SecondaryRATDataUsageReportList().Info(), s46.ERABModifyResponseIEs().UserLocationInformation().Info()}
			s26.BridgeMergeNestedValidation(report, s46.BridgeERABModifyResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(31):
				if value, ok := fields[i].Value.AsERABModifyListBearerModRes(); ok {
					s50.BridgeWalkValidationERABModifyListBearerModRes(value, report, fmt.Sprintf("%s[%d]{id=31}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(32):
				if value, ok := fields[i].Value.AsERABFailedToModifyList(); ok {
					s50.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=32}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s50.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s50.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
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
			rows := []s00.FieldInfo{s46.ERABReleaseIndicationIEs().MMEUES1APID().Info(), s46.ERABReleaseIndicationIEs().ENBUES1APID().Info(), s46.ERABReleaseIndicationIEs().ERABReleasedList().Info(), s46.ERABReleaseIndicationIEs().UserLocationInformation().Info(), s46.ERABReleaseIndicationIEs().SecondaryRATDataUsageReportList().Info()}
			s26.BridgeMergeNestedValidation(report, s46.BridgeERABReleaseIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(110):
				if value, ok := fields[i].Value.AsERABReleasedList(); ok {
					s50.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=110}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s50.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
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
			rows := []s00.FieldInfo{s46.ERABReleaseResponseIEs().MMEUES1APID().Info(), s46.ERABReleaseResponseIEs().ENBUES1APID().Info(), s46.ERABReleaseResponseIEs().ERABReleaseListBearerRelComp().Info(), s46.ERABReleaseResponseIEs().ERABFailedToReleaseList().Info(), s46.ERABReleaseResponseIEs().CriticalityDiagnostics().Info(), s46.ERABReleaseResponseIEs().UserLocationInformation().Info(), s46.ERABReleaseResponseIEs().SecondaryRATDataUsageReportList().Info()}
			s26.BridgeMergeNestedValidation(report, s46.BridgeERABReleaseResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(69):
				if value, ok := fields[i].Value.AsERABReleaseListBearerRelComp(); ok {
					s50.BridgeWalkValidationERABReleaseListBearerRelComp(value, report, fmt.Sprintf("%s[%d]{id=69}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(34):
				if value, ok := fields[i].Value.AsERABFailedToReleaseList(); ok {
					s50.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=34}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s50.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s50.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABSetupResponse(v *s47.ERABSetupResponse, report *s21.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s46.ERABSetupResponseIEs().MMEUES1APID().Info(), s46.ERABSetupResponseIEs().ENBUES1APID().Info(), s46.ERABSetupResponseIEs().ERABSetupListBearerSURes().Info(), s46.ERABSetupResponseIEs().ERABFailedToSetupListBearerSURes().Info(), s46.ERABSetupResponseIEs().CriticalityDiagnostics().Info(), s46.ERABSetupResponseIEs().UserLocationInformation().Info()}
			s26.BridgeMergeNestedValidation(report, s47.BridgeERABSetupResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(28):
				if value, ok := fields[i].Value.AsERABSetupListBearerSURes(); ok {
					s50.BridgeWalkValidationERABSetupListBearerSURes(value, report, fmt.Sprintf("%s[%d]{id=28}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(29):
				if value, ok := fields[i].Value.AsERABFailedToSetupListBearerSURes(); ok {
					s50.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=29}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s50.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
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
			rows := []s00.FieldInfo{s49.HandoverRequestIEs().MMEUES1APID().Info(), s49.HandoverRequestIEs().HandoverType().Info(), s49.HandoverRequestIEs().Cause().Info(), s49.HandoverRequestIEs().UEaggregateMaximumBitrate().Info(), s49.HandoverRequestIEs().ERABToBeSetupListHOReq().Info(), s49.HandoverRequestIEs().SourceToTargetTransparentContainer().Info(), s49.HandoverRequestIEs().UESecurityCapabilities().Info(), s49.HandoverRequestIEs().HandoverRestrictionList().Info(), s49.HandoverRequestIEs().TraceActivation().Info(), s49.HandoverRequestIEs().RequestType().Info(), s49.HandoverRequestIEs().SRVCCOperationPossible().Info(), s49.HandoverRequestIEs().SecurityContext().Info(), s49.HandoverRequestIEs().NASSecurityParameterstoEUTRAN().Info(), s49.HandoverRequestIEs().CSGId().Info(), s49.HandoverRequestIEs().CSGMembershipStatus().Info(), s49.HandoverRequestIEs().GUMMEIID().Info(), s49.HandoverRequestIEs().MMEUES1APID2().Info(), s49.HandoverRequestIEs().ManagementBasedMDTAllowed().Info(), s49.HandoverRequestIEs().ManagementBasedMDTPLMNList().Info(), s49.HandoverRequestIEs().MaskedIMEISV().Info(), s49.HandoverRequestIEs().ExpectedUEBehaviour().Info(), s49.HandoverRequestIEs().ProSeAuthorized().Info(), s49.HandoverRequestIEs().UEUserPlaneCIoTSupportIndicator().Info(), s49.HandoverRequestIEs().V2XServicesAuthorized().Info(), s49.HandoverRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s49.HandoverRequestIEs().EnhancedCoverageRestricted().Info(), s49.HandoverRequestIEs().NRUESecurityCapabilities().Info(), s49.HandoverRequestIEs().CEModeBRestricted().Info(), s49.HandoverRequestIEs().AerialUEsubscriptionInformation().Info(), s49.HandoverRequestIEs().PendingDataIndication().Info(), s49.HandoverRequestIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s49.HandoverRequestIEs().AdditionalRRMPriorityIndex().Info(), s49.HandoverRequestIEs().IABAuthorized().Info(), s49.HandoverRequestIEs().NRV2XServicesAuthorized().Info(), s49.HandoverRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s49.HandoverRequestIEs().PC5QoSParameters().Info(), s49.HandoverRequestIEs().UERadioCapabilityID().Info(), s49.HandoverRequestIEs().TimeRefDistribution().Info()}
			s26.BridgeMergeNestedValidation(report, s49.BridgeHandoverRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s50.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					s50.BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(53):
				if value, ok := fields[i].Value.AsERABToBeSetupListHOReq(); ok {
					s50.BridgeWalkValidationERABToBeSetupListHOReq(value, report, fmt.Sprintf("%s[%d]{id=53}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(107):
				if value, ok := fields[i].Value.AsUESecurityCapabilities(); ok {
					BridgeWalkValidationUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=107}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(41):
				if value, ok := fields[i].Value.AsHandoverRestrictionList(); ok {
					s50.BridgeWalkValidationHandoverRestrictionList(value, report, fmt.Sprintf("%s[%d]{id=41}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(25):
				if value, ok := fields[i].Value.AsTraceActivation(); ok {
					BridgeWalkValidationTraceActivation(value, report, fmt.Sprintf("%s[%d]{id=25}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(98):
				if value, ok := fields[i].Value.AsRequestType(); ok {
					s50.BridgeWalkValidationRequestType(value, report, fmt.Sprintf("%s[%d]{id=98}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(40):
				if value, ok := fields[i].Value.AsSecurityContext(); ok {
					s50.BridgeWalkValidationSecurityContext(value, report, fmt.Sprintf("%s[%d]{id=40}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(75):
				if value, ok := fields[i].Value.AsGUMMEIID(); ok {
					s50.BridgeWalkValidationGUMMEI(value, report, fmt.Sprintf("%s[%d]{id=75}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(177):
				if value, ok := fields[i].Value.AsManagementBasedMDTPLMNList(); ok {
					s50.BridgeWalkValidationMDTPLMNList(value, report, fmt.Sprintf("%s[%d]{id=177}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(196):
				if value, ok := fields[i].Value.AsExpectedUEBehaviour(); ok {
					s50.BridgeWalkValidationExpectedUEBehaviour(value, report, fmt.Sprintf("%s[%d]{id=196}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(195):
				if value, ok := fields[i].Value.AsProSeAuthorized(); ok {
					s50.BridgeWalkValidationProSeAuthorized(value, report, fmt.Sprintf("%s[%d]{id=195}", nestedPath, i), false)
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
					s50.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					s50.BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(306):
				if value, ok := fields[i].Value.AsNRV2XServicesAuthorized(); ok {
					s50.BridgeWalkValidationNRV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=306}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(307):
				if value, ok := fields[i].Value.AsNRUESidelinkAggregateMaximumBitrate(); ok {
					s50.BridgeWalkValidationNRUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=307}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(308):
				if value, ok := fields[i].Value.AsPC5QoSParameters(); ok {
					s50.BridgeWalkValidationPC5QoSParameters(value, report, fmt.Sprintf("%s[%d]{id=308}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationImmediateMDT(v *s48.ImmediateMDT, report *s21.ValidationReport, path string, skipRoot bool) {
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
		s50.BridgeWalkValidationM1ThresholdEventA2(v.M1thresholdeventA2, report, path+".m1thresholdeventA2", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.M1periodicReporting != nil {
		s50.BridgeWalkValidationM1PeriodicReporting(v.M1periodicReporting, report, path+".m1periodicReporting", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s48.ImmediateMDTExtIEs().M3Configuration().Info()), s00.FieldInfo(s48.ImmediateMDTExtIEs().M4Configuration().Info()), s00.FieldInfo(s48.ImmediateMDTExtIEs().M5Configuration().Info()), s00.FieldInfo(s48.ImmediateMDTExtIEs().MDTLocationInfo().Info()), s00.FieldInfo(s48.ImmediateMDTExtIEs().M6Configuration().Info()), s00.FieldInfo(s48.ImmediateMDTExtIEs().M7Configuration().Info()), s00.FieldInfo(s48.ImmediateMDTExtIEs().BluetoothMeasurementConfiguration().Info()), s00.FieldInfo(s48.ImmediateMDTExtIEs().WLANMeasurementConfiguration().Info()), s00.FieldInfo(s48.ImmediateMDTExtIEs().SensorMeasurementConfiguration().Info())}
				s26.BridgeMergeNestedValidation(report, s48.BridgeImmediateMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(171):
					if value, ok := fields[i].ExtensionValue.AsM3Configuration(); ok {
						s50.BridgeWalkValidationM3Configuration(value, report, fmt.Sprintf("%s[%d]{id=171}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(172):
					if value, ok := fields[i].ExtensionValue.AsM4Configuration(); ok {
						s50.BridgeWalkValidationM4Configuration(value, report, fmt.Sprintf("%s[%d]{id=172}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(173):
					if value, ok := fields[i].ExtensionValue.AsM5Configuration(); ok {
						s50.BridgeWalkValidationM5Configuration(value, report, fmt.Sprintf("%s[%d]{id=173}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(220):
					if value, ok := fields[i].ExtensionValue.AsM6Configuration(); ok {
						s50.BridgeWalkValidationM6Configuration(value, report, fmt.Sprintf("%s[%d]{id=220}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(221):
					if value, ok := fields[i].ExtensionValue.AsM7Configuration(); ok {
						s50.BridgeWalkValidationM7Configuration(value, report, fmt.Sprintf("%s[%d]{id=221}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(284):
					if value, ok := fields[i].ExtensionValue.AsBluetoothMeasurementConfiguration(); ok {
						s50.BridgeWalkValidationBluetoothMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=284}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(285):
					if value, ok := fields[i].ExtensionValue.AsWLANMeasurementConfiguration(); ok {
						BridgeWalkValidationWLANMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=285}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(345):
					if value, ok := fields[i].ExtensionValue.AsSensorMeasurementConfiguration(); ok {
						s50.BridgeWalkValidationSensorMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=345}", nestedPath, i), false)
					}
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
			rows := []s00.FieldInfo{s49.InitialContextSetupRequestIEs().MMEUES1APID().Info(), s49.InitialContextSetupRequestIEs().ENBUES1APID().Info(), s49.InitialContextSetupRequestIEs().UEaggregateMaximumBitrate().Info(), s49.InitialContextSetupRequestIEs().ERABToBeSetupListCtxtSUReq().Info(), s49.InitialContextSetupRequestIEs().UESecurityCapabilities().Info(), s49.InitialContextSetupRequestIEs().SecurityKey().Info(), s49.InitialContextSetupRequestIEs().TraceActivation().Info(), s49.InitialContextSetupRequestIEs().HandoverRestrictionList().Info(), s49.InitialContextSetupRequestIEs().UERadioCapability().Info(), s49.InitialContextSetupRequestIEs().SubscriberProfileIDforRFP().Info(), s49.InitialContextSetupRequestIEs().CSFallbackIndicator().Info(), s49.InitialContextSetupRequestIEs().SRVCCOperationPossible().Info(), s49.InitialContextSetupRequestIEs().CSGMembershipStatus().Info(), s49.InitialContextSetupRequestIEs().RegisteredLAI().Info(), s49.InitialContextSetupRequestIEs().GUMMEIID().Info(), s49.InitialContextSetupRequestIEs().MMEUES1APID2().Info(), s49.InitialContextSetupRequestIEs().ManagementBasedMDTAllowed().Info(), s49.InitialContextSetupRequestIEs().ManagementBasedMDTPLMNList().Info(), s49.InitialContextSetupRequestIEs().AdditionalCSFallbackIndicator().Info(), s49.InitialContextSetupRequestIEs().MaskedIMEISV().Info(), s49.InitialContextSetupRequestIEs().ExpectedUEBehaviour().Info(), s49.InitialContextSetupRequestIEs().ProSeAuthorized().Info(), s49.InitialContextSetupRequestIEs().UEUserPlaneCIoTSupportIndicator().Info(), s49.InitialContextSetupRequestIEs().V2XServicesAuthorized().Info(), s49.InitialContextSetupRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s49.InitialContextSetupRequestIEs().EnhancedCoverageRestricted().Info(), s49.InitialContextSetupRequestIEs().NRUESecurityCapabilities().Info(), s49.InitialContextSetupRequestIEs().CEModeBRestricted().Info(), s49.InitialContextSetupRequestIEs().AerialUEsubscriptionInformation().Info(), s49.InitialContextSetupRequestIEs().PendingDataIndication().Info(), s49.InitialContextSetupRequestIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s49.InitialContextSetupRequestIEs().AdditionalRRMPriorityIndex().Info(), s49.InitialContextSetupRequestIEs().IABAuthorized().Info(), s49.InitialContextSetupRequestIEs().NRV2XServicesAuthorized().Info(), s49.InitialContextSetupRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s49.InitialContextSetupRequestIEs().PC5QoSParameters().Info(), s49.InitialContextSetupRequestIEs().UERadioCapabilityID().Info(), s49.InitialContextSetupRequestIEs().CoarseUELocation().Info(), s49.InitialContextSetupRequestIEs().TimeRefDistribution().Info()}
			s26.BridgeMergeNestedValidation(report, s49.BridgeInitialContextSetupRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					s50.BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(24):
				if value, ok := fields[i].Value.AsERABToBeSetupListCtxtSUReq(); ok {
					s50.BridgeWalkValidationERABToBeSetupListCtxtSUReq(value, report, fmt.Sprintf("%s[%d]{id=24}", nestedPath, i), false)
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
					s50.BridgeWalkValidationHandoverRestrictionList(value, report, fmt.Sprintf("%s[%d]{id=41}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(159):
				if value, ok := fields[i].Value.AsRegisteredLAI(); ok {
					s50.BridgeWalkValidationLAI(value, report, fmt.Sprintf("%s[%d]{id=159}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(75):
				if value, ok := fields[i].Value.AsGUMMEIID(); ok {
					s50.BridgeWalkValidationGUMMEI(value, report, fmt.Sprintf("%s[%d]{id=75}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(177):
				if value, ok := fields[i].Value.AsManagementBasedMDTPLMNList(); ok {
					s50.BridgeWalkValidationMDTPLMNList(value, report, fmt.Sprintf("%s[%d]{id=177}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(196):
				if value, ok := fields[i].Value.AsExpectedUEBehaviour(); ok {
					s50.BridgeWalkValidationExpectedUEBehaviour(value, report, fmt.Sprintf("%s[%d]{id=196}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(195):
				if value, ok := fields[i].Value.AsProSeAuthorized(); ok {
					s50.BridgeWalkValidationProSeAuthorized(value, report, fmt.Sprintf("%s[%d]{id=195}", nestedPath, i), false)
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
					s50.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					s50.BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(306):
				if value, ok := fields[i].Value.AsNRV2XServicesAuthorized(); ok {
					s50.BridgeWalkValidationNRV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=306}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(307):
				if value, ok := fields[i].Value.AsNRUESidelinkAggregateMaximumBitrate(); ok {
					s50.BridgeWalkValidationNRUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=307}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(308):
				if value, ok := fields[i].Value.AsPC5QoSParameters(); ok {
					s50.BridgeWalkValidationPC5QoSParameters(value, report, fmt.Sprintf("%s[%d]{id=308}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
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
			s26.BridgeMergeNestedValidation(report, s33.BridgeKillRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationLoggedMDT(v *s48.LoggedMDT, report *s21.ValidationReport, path string, skipRoot bool) {
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
				rows := []s00.FieldInfo{s00.FieldInfo(s48.LoggedMDTExtIEs().BluetoothMeasurementConfiguration().Info()), s00.FieldInfo(s48.LoggedMDTExtIEs().WLANMeasurementConfiguration().Info()), s00.FieldInfo(s48.LoggedMDTExtIEs().LoggedMDTTrigger().Info()), s00.FieldInfo(s48.LoggedMDTExtIEs().SensorMeasurementConfiguration().Info())}
				s26.BridgeMergeNestedValidation(report, s48.BridgeLoggedMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(284):
					if value, ok := fields[i].ExtensionValue.AsBluetoothMeasurementConfiguration(); ok {
						s50.BridgeWalkValidationBluetoothMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=284}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(285):
					if value, ok := fields[i].ExtensionValue.AsWLANMeasurementConfiguration(); ok {
						BridgeWalkValidationWLANMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=285}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(344):
					if value, ok := fields[i].ExtensionValue.AsLoggedMDTTrigger(); ok {
						s50.BridgeWalkValidationLoggedMDTTrigger(value, report, fmt.Sprintf("%s[%d]{id=344}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(345):
					if value, ok := fields[i].ExtensionValue.AsSensorMeasurementConfiguration(); ok {
						s50.BridgeWalkValidationSensorMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=345}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMDTConfiguration(v *s48.MDTConfiguration, report *s21.ValidationReport, path string, skipRoot bool) {
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
	s50.BridgeWalkValidationAreaScopeOfMDT(&v.AreaScopeOfMDT, report, path+".areaScopeOfMDT", false)
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
				s26.BridgeMergeNestedValidation(report, s42.BridgeMDTConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(178):
					if value, ok := fields[i].ExtensionValue.AsSignallingBasedMDTPLMNList(); ok {
						s50.BridgeWalkValidationMDTPLMNList(value, report, fmt.Sprintf("%s[%d]{id=178}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMDTMode(v *s48.MDTMode, report *s21.ValidationReport, path string, skipRoot bool) {
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
		s50.BridgeWalkValidationMDTModeExtension(v.MDTModeExtension, report, path+".mDTMode-Extension", false)
	}
}
func BridgeWalkValidationPaging(v *s50.Paging, report *s21.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s50.PagingIEs().UEIdentityIndexValue().Info(), s50.PagingIEs().UEPagingID().Info(), s50.PagingIEs().PagingDRX().Info(), s50.PagingIEs().CNDomain().Info(), s50.PagingIEs().TAIList().Info(), s50.PagingIEs().CSGIdList().Info(), s50.PagingIEs().PagingPriority().Info(), s50.PagingIEs().UERadioCapabilityForPaging().Info(), s50.PagingIEs().AssistanceDataForPaging().Info(), s50.PagingIEs().PagingEDRXInformation().Info(), s50.PagingIEs().ExtendedUEIdentityIndexValue().Info(), s50.PagingIEs().NBIoTPagingEDRXInformation().Info(), s50.PagingIEs().NBIoTUEIdentityIndexValue().Info(), s50.PagingIEs().EnhancedCoverageRestricted().Info(), s50.PagingIEs().CEModeBRestricted().Info(), s50.PagingIEs().DataSize().Info(), s50.PagingIEs().WUSAssistanceInformation().Info(), s50.PagingIEs().NBIoTPagingDRX().Info(), s50.PagingIEs().PagingCause().Info()}
			s26.BridgeMergeNestedValidation(report, s50.BridgePagingIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
					s50.BridgeWalkValidationTAIList(value, report, fmt.Sprintf("%s[%d]{id=46}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(128):
				if value, ok := fields[i].Value.AsCSGIdList(); ok {
					s50.BridgeWalkValidationCSGIdList(value, report, fmt.Sprintf("%s[%d]{id=128}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(211):
				if value, ok := fields[i].Value.AsAssistanceDataForPaging(); ok {
					s50.BridgeWalkValidationAssistanceDataForPaging(value, report, fmt.Sprintf("%s[%d]{id=211}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(227):
				if value, ok := fields[i].Value.AsPagingEDRXInformation(); ok {
					s50.BridgeWalkValidationPagingEDRXInformation(value, report, fmt.Sprintf("%s[%d]{id=227}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(239):
				if value, ok := fields[i].Value.AsNBIoTPagingEDRXInformation(); ok {
					s50.BridgeWalkValidationNBIoTPagingEDRXInformation(value, report, fmt.Sprintf("%s[%d]{id=239}", nestedPath, i), false)
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
			s26.BridgeMergeNestedValidation(report, s42.BridgePathSwitchRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(22):
				if value, ok := fields[i].Value.AsERABToBeSwitchedDLList(); ok {
					s50.BridgeWalkValidationERABToBeSwitchedDLList(value, report, fmt.Sprintf("%s[%d]{id=22}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					s50.BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					s50.BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(107):
				if value, ok := fields[i].Value.AsUESecurityCapabilities(); ok {
					BridgeWalkValidationUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=107}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(157):
				if value, ok := fields[i].Value.AsSourceMMEGUMMEI(); ok {
					s50.BridgeWalkValidationGUMMEI(value, report, fmt.Sprintf("%s[%d]{id=157}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(176):
				if value, ok := fields[i].Value.AsTunnelInformationForBBF(); ok {
					s50.BridgeWalkValidationTunnelInformation(value, report, fmt.Sprintf("%s[%d]{id=176}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(269):
				if value, ok := fields[i].Value.AsNRUESecurityCapabilities(); ok {
					s50.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(288):
				if value, ok := fields[i].Value.AsPSCellInformation(); ok {
					s50.BridgeWalkValidationPSCellInformation(value, report, fmt.Sprintf("%s[%d]{id=288}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					s50.BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPathSwitchRequestAcknowledge(v *s48.PathSwitchRequestAcknowledge, report *s21.ValidationReport, path string, skipRoot bool) {
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
			s26.BridgeMergeNestedValidation(report, s48.BridgePathSwitchRequestAcknowledgeIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					s50.BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(95):
				if value, ok := fields[i].Value.AsERABToBeSwitchedULList(); ok {
					s50.BridgeWalkValidationERABToBeSwitchedULList(value, report, fmt.Sprintf("%s[%d]{id=95}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(33):
				if value, ok := fields[i].Value.AsERABToBeReleasedList(); ok {
					s50.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=33}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(40):
				if value, ok := fields[i].Value.AsSecurityContext(); ok {
					s50.BridgeWalkValidationSecurityContext(value, report, fmt.Sprintf("%s[%d]{id=40}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s50.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(195):
				if value, ok := fields[i].Value.AsProSeAuthorized(); ok {
					s50.BridgeWalkValidationProSeAuthorized(value, report, fmt.Sprintf("%s[%d]{id=195}", nestedPath, i), false)
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
					s50.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					s50.BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(41):
				if value, ok := fields[i].Value.AsHandoverRestrictionList(); ok {
					s50.BridgeWalkValidationHandoverRestrictionList(value, report, fmt.Sprintf("%s[%d]{id=41}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(306):
				if value, ok := fields[i].Value.AsNRV2XServicesAuthorized(); ok {
					s50.BridgeWalkValidationNRV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=306}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(307):
				if value, ok := fields[i].Value.AsNRUESidelinkAggregateMaximumBitrate(); ok {
					s50.BridgeWalkValidationNRUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=307}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(308):
				if value, ok := fields[i].Value.AsPC5QoSParameters(); ok {
					s50.BridgeWalkValidationPC5QoSParameters(value, report, fmt.Sprintf("%s[%d]{id=308}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(107):
				if value, ok := fields[i].Value.AsUESecurityCapabilities(); ok {
					BridgeWalkValidationUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=107}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(341):
				if value, ok := fields[i].Value.AsERABToBeUpdatedList(); ok {
					s50.BridgeWalkValidationERABToBeUpdatedList(value, report, fmt.Sprintf("%s[%d]{id=341}", nestedPath, i), false)
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
			s26.BridgeMergeNestedValidation(report, s36.BridgeResetIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s50.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
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
func BridgeWalkValidationResetAcknowledge(v *s45.ResetAcknowledge, report *s21.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s45.ResetAcknowledgeIEs().UEAssociatedLogicalS1ConnectionListResAck().Info(), s45.ResetAcknowledgeIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s45.BridgeResetAcknowledgeIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
					s50.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
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
func BridgeWalkValidationSecondaryRATDataUsageReport(v *s47.SecondaryRATDataUsageReport, report *s21.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s46.SecondaryRATDataUsageReportIEs().MMEUES1APID().Info(), s46.SecondaryRATDataUsageReportIEs().ENBUES1APID().Info(), s46.SecondaryRATDataUsageReportIEs().SecondaryRATDataUsageReportList().Info(), s46.SecondaryRATDataUsageReportIEs().HandoverFlag().Info(), s46.SecondaryRATDataUsageReportIEs().UserLocationInformation().Info(), s46.SecondaryRATDataUsageReportIEs().TimeSinceSecondaryNodeRelease().Info()}
			s26.BridgeMergeNestedValidation(report, s47.BridgeSecondaryRATDataUsageReportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s50.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
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
		s50.BridgeWalkValidationERABInformationList(&v.ERABInformationList, report, path+".e-RABInformationList", false)
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s50.BridgeWalkValidationEUTRANCGI(&v.TargetCellID, report, path+".targetCell-ID", false)
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
				rows := []s00.FieldInfo{s00.FieldInfo(s35.SourceeNBToTargeteNBTransparentContainerExtIEs().MobilityInformation().Info()), s00.FieldInfo(s35.SourceeNBToTargeteNBTransparentContainerExtIEs().UEHistoryInformationFromTheUE().Info()), s00.FieldInfo(s35.SourceeNBToTargeteNBTransparentContainerExtIEs().IMSvoiceEPSfallbackfrom5G().Info()), s00.FieldInfo(s35.SourceeNBToTargeteNBTransparentContainerExtIEs().AdditionalRRMPriorityIndex().Info()), s00.FieldInfo(s35.SourceeNBToTargeteNBTransparentContainerExtIEs().ContextatSource().Info()), s00.FieldInfo(s35.SourceeNBToTargeteNBTransparentContainerExtIEs().IntersystemMeasurementConfiguration().Info()), s00.FieldInfo(s35.SourceeNBToTargeteNBTransparentContainerExtIEs().SourceNodeID().Info()), s00.FieldInfo(s35.SourceeNBToTargeteNBTransparentContainerExtIEs().EmergencyIndicator().Info()), s00.FieldInfo(s35.SourceeNBToTargeteNBTransparentContainerExtIEs().UEContextReferenceatSourceeNB().Info()), s00.FieldInfo(s35.SourceeNBToTargeteNBTransparentContainerExtIEs().SourceSNID().Info()), s00.FieldInfo(s35.SourceeNBToTargeteNBTransparentContainerExtIEs().DirectForwardingPathAvailability().Info()), s00.FieldInfo(s35.SourceeNBToTargeteNBTransparentContainerExtIEs().TimeBasedHandoverInformation().Info())}
				s26.BridgeMergeNestedValidation(report, s35.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(300):
					if value, ok := fields[i].ExtensionValue.AsContextatSource(); ok {
						s50.BridgeWalkValidationContextatSource(value, report, fmt.Sprintf("%s[%d]{id=300}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(311):
					if value, ok := fields[i].ExtensionValue.AsIntersystemMeasurementConfiguration(); ok {
						s50.BridgeWalkValidationIntersystemMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=311}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(312):
					if value, ok := fields[i].ExtensionValue.AsSourceNodeID(); ok {
						s50.BridgeWalkValidationSourceNodeID(value, report, fmt.Sprintf("%s[%d]{id=312}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(343):
					if value, ok := fields[i].ExtensionValue.AsSourceSNID(); ok {
						s50.BridgeWalkValidationGlobalRANNODEID(value, report, fmt.Sprintf("%s[%d]{id=343}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(350):
					if value, ok := fields[i].ExtensionValue.AsTimeBasedHandoverInformation(); ok {
						s50.BridgeWalkValidationTimeBasedHandoverInformation(value, report, fmt.Sprintf("%s[%d]{id=350}", nestedPath, i), false)
					}
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
func BridgeWalkValidationTraceActivation(v *s48.TraceActivation, report *s21.ValidationReport, path string, skipRoot bool) {
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
				rows := []s00.FieldInfo{s00.FieldInfo(s48.TraceActivationExtIEs().MDTConfiguration().Info()), s00.FieldInfo(s48.TraceActivationExtIEs().UEAppLayerMeasConfig().Info()), s00.FieldInfo(s48.TraceActivationExtIEs().MDTConfigurationNR().Info()), s00.FieldInfo(s48.TraceActivationExtIEs().TraceCollectionEntityURI().Info())}
				s26.BridgeMergeNestedValidation(report, s49.BridgeTraceActivationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
						s50.BridgeWalkValidationUEAppLayerMeasConfig(value, report, fmt.Sprintf("%s[%d]{id=262}", nestedPath, i), false)
					}
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
			s26.BridgeMergeNestedValidation(report, s49.BridgeTraceStartIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationUEAssociatedLogicalS1ConnectionItem(v *s36.UEAssociatedLogicalS1ConnectionItem, report *s21.ValidationReport, path string, skipRoot bool) {
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
				s26.BridgeMergeNestedValidation(report, s36.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
		rows := []s00.FieldInfo{s36.UEAssociatedLogicalS1ConnectionItemRes().UEAssociatedLogicalS1ConnectionItem().Info()}
		s26.BridgeMergeNestedValidation(report, s36.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueValidateS1APIEContainer(s36.UEAssociatedLogicalS1ConnectionItemResIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s36.UEAssociatedLogicalS1ConnectionItemResIEContainer{field}
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
		rows := []s00.FieldInfo{s36.UEAssociatedLogicalS1ConnectionItemResAck().UEAssociatedLogicalS1ConnectionItem().Info()}
		s26.BridgeMergeNestedValidation(report, s36.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueValidateS1APIEContainer(s36.UEAssociatedLogicalS1ConnectionItemResAckIEContainer{field}, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		fields := s36.UEAssociatedLogicalS1ConnectionItemResAckIEContainer{field}
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
			s26.BridgeMergeNestedValidation(report, s36.BridgeUECapabilityInfoIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
			s26.BridgeMergeNestedValidation(report, s36.BridgeUEContextModificationConfirmIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s50.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
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
			s26.BridgeMergeNestedValidation(report, s37.BridgeUEContextModificationFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s50.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s50.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextModificationIndication(v *s37.UEContextModificationIndication, report *s21.ValidationReport, path string, skipRoot bool) {
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
			s26.BridgeMergeNestedValidation(report, s37.BridgeUEContextModificationIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(226):
				if value, ok := fields[i].Value.AsCSGMembershipInfo(); ok {
					s50.BridgeWalkValidationCSGMembershipInfo(value, report, fmt.Sprintf("%s[%d]{id=226}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextModificationRequest(v *s48.UEContextModificationRequest, report *s21.ValidationReport, path string, skipRoot bool) {
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
			s26.BridgeMergeNestedValidation(report, s48.BridgeUEContextModificationRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					s50.BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(107):
				if value, ok := fields[i].Value.AsUESecurityCapabilities(); ok {
					BridgeWalkValidationUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=107}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(159):
				if value, ok := fields[i].Value.AsRegisteredLAI(); ok {
					s50.BridgeWalkValidationLAI(value, report, fmt.Sprintf("%s[%d]{id=159}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(195):
				if value, ok := fields[i].Value.AsProSeAuthorized(); ok {
					s50.BridgeWalkValidationProSeAuthorized(value, report, fmt.Sprintf("%s[%d]{id=195}", nestedPath, i), false)
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
					s50.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(306):
				if value, ok := fields[i].Value.AsNRV2XServicesAuthorized(); ok {
					s50.BridgeWalkValidationNRV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=306}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(307):
				if value, ok := fields[i].Value.AsNRUESidelinkAggregateMaximumBitrate(); ok {
					s50.BridgeWalkValidationNRUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=307}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(308):
				if value, ok := fields[i].Value.AsPC5QoSParameters(); ok {
					s50.BridgeWalkValidationPC5QoSParameters(value, report, fmt.Sprintf("%s[%d]{id=308}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextModificationResponse(v *s37.UEContextModificationResponse, report *s21.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s24.UEContextModificationResponseIEs().MMEUES1APID().Info(), s24.UEContextModificationResponseIEs().ENBUES1APID().Info(), s24.UEContextModificationResponseIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s37.BridgeUEContextModificationResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s50.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
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
			s26.BridgeMergeNestedValidation(report, s37.BridgeUEContextReleaseCommandIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
					s50.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextReleaseComplete(v *s47.UEContextReleaseComplete, report *s21.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s46.UEContextReleaseCompleteIEs().MMEUES1APID().Info(), s46.UEContextReleaseCompleteIEs().ENBUES1APID().Info(), s46.UEContextReleaseCompleteIEs().CriticalityDiagnostics().Info(), s46.UEContextReleaseCompleteIEs().UserLocationInformation().Info(), s46.UEContextReleaseCompleteIEs().InformationOnRecommendedCellsAndENBsForPaging().Info(), s46.UEContextReleaseCompleteIEs().CellIdentifierAndCELevelForCECapableUEs().Info(), s46.UEContextReleaseCompleteIEs().SecondaryRATDataUsageReportList().Info(), s46.UEContextReleaseCompleteIEs().TimeSinceSecondaryNodeRelease().Info()}
			s26.BridgeMergeNestedValidation(report, s47.BridgeUEContextReleaseCompleteIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s50.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(213):
				if value, ok := fields[i].Value.AsInformationOnRecommendedCellsAndENBsForPaging(); ok {
					s50.BridgeWalkValidationInformationOnRecommendedCellsAndENBsForPaging(value, report, fmt.Sprintf("%s[%d]{id=213}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(212):
				if value, ok := fields[i].Value.AsCellIdentifierAndCELevelForCECapableUEs(); ok {
					s50.BridgeWalkValidationCellIdentifierAndCELevelForCECapableUEs(value, report, fmt.Sprintf("%s[%d]{id=212}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s50.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
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
			s26.BridgeMergeNestedValidation(report, s43.BridgeUEContextReleaseRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s50.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s50.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextResumeFailure(v *s37.UEContextResumeFailure, report *s21.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s24.UEContextResumeFailureIEs().MMEUES1APID().Info(), s24.UEContextResumeFailureIEs().ENBUES1APID().Info(), s24.UEContextResumeFailureIEs().Cause().Info(), s24.UEContextResumeFailureIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, s37.BridgeUEContextResumeFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s50.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s50.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextResumeRequest(v *s39.UEContextResumeRequest, report *s21.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s39.UEContextResumeRequestIEs().MMEUES1APID().Info(), s39.UEContextResumeRequestIEs().ENBUES1APID().Info(), s39.UEContextResumeRequestIEs().ERABFailedToResumeListResumeReq().Info(), s39.UEContextResumeRequestIEs().RRCResumeCause().Info()}
			s26.BridgeMergeNestedValidation(report, s39.BridgeUEContextResumeRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(235):
				if value, ok := fields[i].Value.AsERABFailedToResumeListResumeReq(); ok {
					s50.BridgeWalkValidationERABFailedToResumeListResumeReq(value, report, fmt.Sprintf("%s[%d]{id=235}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextResumeResponse(v *s39.UEContextResumeResponse, report *s21.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s39.UEContextResumeResponseIEs().MMEUES1APID().Info(), s39.UEContextResumeResponseIEs().ENBUES1APID().Info(), s39.UEContextResumeResponseIEs().ERABFailedToResumeListResumeRes().Info(), s39.UEContextResumeResponseIEs().CriticalityDiagnostics().Info(), s39.UEContextResumeResponseIEs().SecurityContext().Info(), s39.UEContextResumeResponseIEs().PendingDataIndication().Info()}
			s26.BridgeMergeNestedValidation(report, s39.BridgeUEContextResumeResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(237):
				if value, ok := fields[i].Value.AsERABFailedToResumeListResumeRes(); ok {
					s50.BridgeWalkValidationERABFailedToResumeListResumeRes(value, report, fmt.Sprintf("%s[%d]{id=237}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s50.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(40):
				if value, ok := fields[i].Value.AsSecurityContext(); ok {
					s50.BridgeWalkValidationSecurityContext(value, report, fmt.Sprintf("%s[%d]{id=40}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextSuspendRequest(v *s47.UEContextSuspendRequest, report *s21.ValidationReport, path string, skipRoot bool) {
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
			s26.BridgeMergeNestedValidation(report, s47.BridgeUEContextSuspendRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(213):
				if value, ok := fields[i].Value.AsInformationOnRecommendedCellsAndENBsForPaging(); ok {
					s50.BridgeWalkValidationInformationOnRecommendedCellsAndENBsForPaging(value, report, fmt.Sprintf("%s[%d]{id=213}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(212):
				if value, ok := fields[i].Value.AsCellIdentifierAndCELevelForCECapableUEs(); ok {
					s50.BridgeWalkValidationCellIdentifierAndCELevelForCECapableUEs(value, report, fmt.Sprintf("%s[%d]{id=212}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s50.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
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
func BridgeWalkValidationUEContextSuspendResponse(v *s37.UEContextSuspendResponse, report *s21.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s29.UEContextSuspendResponseIEs().MMEUES1APID().Info(), s29.UEContextSuspendResponseIEs().ENBUES1APID().Info(), s29.UEContextSuspendResponseIEs().CriticalityDiagnostics().Info(), s29.UEContextSuspendResponseIEs().SecurityContext().Info()}
			s26.BridgeMergeNestedValidation(report, s37.BridgeUEContextSuspendResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s50.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(40):
				if value, ok := fields[i].Value.AsSecurityContext(); ok {
					s50.BridgeWalkValidationSecurityContext(value, report, fmt.Sprintf("%s[%d]{id=40}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEHistoryInformation(v *s42.UEHistoryInformation, report *s21.ValidationReport, path string, skipRoot bool) {
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
		s50.BridgeWalkValidationLastVisitedCellItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationUEInformationTransfer(v *s37.UEInformationTransfer, report *s21.ValidationReport, path string, skipRoot bool) {
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
			s26.BridgeMergeNestedValidation(report, s37.BridgeUEInformationTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(96):
				if value, ok := fields[i].Value.AsSTMSI(); ok {
					s50.BridgeWalkValidationSTMSI(value, report, fmt.Sprintf("%s[%d]{id=96}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(252):
				if value, ok := fields[i].Value.AsUELevelQoSParameters(); ok {
					s50.BridgeWalkValidationERABLevelQoSParameters(value, report, fmt.Sprintf("%s[%d]{id=252}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					s50.BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
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
		s50.BridgeWalkValidationSTMSI(v.STMSI, report, path+".s-TMSI", false)
	}
}
func BridgeWalkValidationUERadioCapabilityIDMappingRequest(v *s37.UERadioCapabilityIDMappingRequest, report *s21.ValidationReport, path string, skipRoot bool) {
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
			s26.BridgeMergeNestedValidation(report, s37.BridgeUERadioCapabilityIDMappingRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationUERadioCapabilityIDMappingResponse(v *s37.UERadioCapabilityIDMappingResponse, report *s21.ValidationReport, path string, skipRoot bool) {
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
			s26.BridgeMergeNestedValidation(report, s37.BridgeUERadioCapabilityIDMappingResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s50.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUERadioCapabilityMatchRequest(v *s37.UERadioCapabilityMatchRequest, report *s21.ValidationReport, path string, skipRoot bool) {
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
			s26.BridgeMergeNestedValidation(report, s37.BridgeUERadioCapabilityMatchRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
			s26.BridgeMergeNestedValidation(report, s37.BridgeUERadioCapabilityMatchResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s50.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
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
				s26.BridgeMergeNestedValidation(report, s37.BridgeUES1APIDPairExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
				s26.BridgeMergeNestedValidation(report, s37.BridgeUESecurityCapabilitiesExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationUESidelinkAggregateMaximumBitrate(v *s38.UESidelinkAggregateMaximumBitrate, report *s21.ValidationReport, path string, skipRoot bool) {
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
				s26.BridgeMergeNestedValidation(report, s38.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationULCPSecurityInformation(v *s38.ULCPSecurityInformation, report *s21.ValidationReport, path string, skipRoot bool) {
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
				s26.BridgeMergeNestedValidation(report, s38.BridgeULCPSecurityInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationUnsuccessfulOutcome(v *s37.UnsuccessfulOutcome, report *s21.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationUplinkNASTransport(v *s45.UplinkNASTransport, report *s21.ValidationReport, path string, skipRoot bool) {
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
			s26.BridgeMergeNestedValidation(report, s45.BridgeUplinkNASTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					s50.BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					s50.BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(288):
				if value, ok := fields[i].Value.AsPSCellInformation(); ok {
					s50.BridgeWalkValidationPSCellInformation(value, report, fmt.Sprintf("%s[%d]{id=288}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					s50.BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUplinkNonUEAssociatedLPPaTransport(v *s45.UplinkNonUEAssociatedLPPaTransport, report *s21.ValidationReport, path string, skipRoot bool) {
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
			s26.BridgeMergeNestedValidation(report, s45.BridgeUplinkNonUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationUplinkS1cdma2000tunnelling(v *s45.UplinkS1cdma2000tunnelling, report *s21.ValidationReport, path string, skipRoot bool) {
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
			s26.BridgeMergeNestedValidation(report, s45.BridgeUplinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(102):
				if value, ok := fields[i].Value.AsCdma2000OneXSRVCCInfo(); ok {
					s50.BridgeWalkValidationCdma2000OneXSRVCCInfo(value, report, fmt.Sprintf("%s[%d]{id=102}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUplinkUEAssociatedLPPaTransport(v *s45.UplinkUEAssociatedLPPaTransport, report *s21.ValidationReport, path string, skipRoot bool) {
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
			s26.BridgeMergeNestedValidation(report, s45.BridgeUplinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationUserLocationInformation(v *s45.UserLocationInformation, report *s21.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s21.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s21.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s50.BridgeWalkValidationEUTRANCGI(&v.EutranCgi, report, path+".eutran-cgi", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s50.BridgeWalkValidationTAI(&v.Tai, report, path+".tai", false)
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s21.UserLocationInformationExtIEs().PSCellInformation().Info()), s00.FieldInfo(s21.UserLocationInformationExtIEs().LTENTNTAIInformation().Info())}
				s26.BridgeMergeNestedValidation(report, s47.BridgeUserLocationInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s21.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(288):
					if value, ok := fields[i].ExtensionValue.AsPSCellInformation(); ok {
						s50.BridgeWalkValidationPSCellInformation(value, report, fmt.Sprintf("%s[%d]{id=288}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(339):
					if value, ok := fields[i].ExtensionValue.AsLTENTNTAIInformation(); ok {
						s50.BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationV2XServicesAuthorized(v *s47.V2XServicesAuthorized, report *s21.ValidationReport, path string, skipRoot bool) {
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
				s26.BridgeMergeNestedValidation(report, s48.BridgeV2XServicesAuthorizedExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationWLANMeasurementConfiguration(v *s48.WLANMeasurementConfiguration, report *s21.ValidationReport, path string, skipRoot bool) {
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
				s26.BridgeMergeNestedValidation(report, s49.BridgeWLANMeasurementConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
				s26.BridgeMergeNestedValidation(report, s50.BridgeWUSAssistanceInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationWarningAreaList(v *s33.WarningAreaList, report *s21.ValidationReport, path string, skipRoot bool) {
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
		s50.BridgeWalkValidationECGIList(&v.CellIDList, report, path+".cellIDList", false)
	}
	if v.Choice == s00.WarningAreaListChoiceTrackingAreaListforWarning && v.TrackingAreaListforWarning != nil {
		s50.BridgeWalkValidationTAIListforWarning(&v.TrackingAreaListforWarning, report, path+".trackingAreaListforWarning", false)
	}
	if v.Choice == s00.WarningAreaListChoiceEmergencyAreaIDList && v.EmergencyAreaIDList != nil {
		s50.BridgeWalkValidationEmergencyAreaIDList(&v.EmergencyAreaIDList, report, path+".emergencyAreaIDList", false)
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
			s26.BridgeMergeNestedValidation(report, BridgeWriteReplaceWarningRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
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
			rows := []s00.FieldInfo{s33.WriteReplaceWarningResponseIEs().MessageIdentifier().Info(), s33.WriteReplaceWarningResponseIEs().SerialNumber().Info(), s33.WriteReplaceWarningResponseIEs().BroadcastCompletedAreaList().Info(), s33.WriteReplaceWarningResponseIEs().CriticalityDiagnostics().Info()}
			s26.BridgeMergeNestedValidation(report, BridgeWriteReplaceWarningResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s21.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s21.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(120):
				if value, ok := fields[i].Value.AsBroadcastCompletedAreaList(); ok {
					s50.BridgeWalkValidationBroadcastCompletedAreaList(value, report, fmt.Sprintf("%s[%d]{id=120}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s50.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s21.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeENBConfigurationTransferENDCSONConfigurationTransferIEBindingFieldCodec(v *ENBConfigurationTransferENDCSONConfigurationTransferIEBinding) *ENDCSONConfigurationTransferValueCodec {
	return &v.codec
}
func BridgeENBConfigurationTransferENDCSONConfigurationTransferIEBindingFieldGet(v *ENBConfigurationTransferENDCSONConfigurationTransferIEBinding) *func(*ENBConfigurationTransferIEValue) (*ENDCSONConfigurationTransfer, bool) {
	return &v.get
}
func BridgeENBConfigurationTransferENDCSONConfigurationTransferIEBindingFieldInfo(v *ENBConfigurationTransferENDCSONConfigurationTransferIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBConfigurationTransferENDCSONConfigurationTransferIEBindingFieldInject(v *ENBConfigurationTransferENDCSONConfigurationTransferIEBinding) *func(ENDCSONConfigurationTransfer) ENBConfigurationTransferIEValue {
	return &v.inject
}
func BridgeENBConfigurationTransferIEContainerAPERValueFieldContext(v *ENBConfigurationTransferIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationTransferIEContainerAPERValueFieldReceived(v *ENBConfigurationTransferIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationTransferIEContainerAPERValueFieldReplay(v *ENBConfigurationTransferIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationTransferIEContainerAPERValueFieldWithoutReplay(v *ENBConfigurationTransferIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationTransferIEContainerValueCodecFieldCapture(v *ENBConfigurationTransferIEContainerValueCodec) *func(ENBConfigurationTransferIEContainer, aper.DecodeState) (ENBConfigurationTransferIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationTransferIEContainerValueCodecFieldCompare(v *ENBConfigurationTransferIEContainerValueCodec) *func(ENBConfigurationTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationTransferIEContainerValueCodecFieldContext(v *ENBConfigurationTransferIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationTransferIEContainerValueCodecFieldDecode(v *ENBConfigurationTransferIEContainerValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationTransferIEContainer, error) {
	return &v.decode
}
func BridgeENBConfigurationTransferIEContainerValueCodecFieldEncode(v *ENBConfigurationTransferIEContainerValueCodec) *func(ENBConfigurationTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationTransferIEContainerValueCodecFieldPath(v *ENBConfigurationTransferIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationTransferIEContainerValueCodecMethodEncodeBudgetValue(v ENBConfigurationTransferIEContainerValueCodec, a0 ENBConfigurationTransferIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationTransferIEContainerValueCodecMethodEncodeChanged(v ENBConfigurationTransferIEContainerValueCodec, a0 ENBConfigurationTransferIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationTransferIEFieldAPERValueFieldContext(v *ENBConfigurationTransferIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationTransferIEFieldAPERValueFieldReceived(v *ENBConfigurationTransferIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationTransferIEFieldAPERValueFieldReplay(v *ENBConfigurationTransferIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationTransferIEFieldAPERValueFieldWithoutReplay(v *ENBConfigurationTransferIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationTransferIEFieldFieldReceived(v *ENBConfigurationTransferIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeENBConfigurationTransferIEFieldFieldReplay(v *ENBConfigurationTransferIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationTransferIEFieldFieldStream(v *ENBConfigurationTransferIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeENBConfigurationTransferIEFieldFieldWithoutReplay(v *ENBConfigurationTransferIEField) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationTransferIEFieldMethodMarshalAPERTo(v *ENBConfigurationTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENBConfigurationTransferIEFieldMethodUnmarshalAPERFrom(v *ENBConfigurationTransferIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENBConfigurationTransferIEFieldValueCodecFieldCapture(v *ENBConfigurationTransferIEFieldValueCodec) *func(ENBConfigurationTransferIEField, aper.DecodeState) (ENBConfigurationTransferIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationTransferIEFieldValueCodecFieldCompare(v *ENBConfigurationTransferIEFieldValueCodec) *func(ENBConfigurationTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationTransferIEFieldValueCodecFieldContext(v *ENBConfigurationTransferIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationTransferIEFieldValueCodecFieldDecode(v *ENBConfigurationTransferIEFieldValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationTransferIEField, error) {
	return &v.decode
}
func BridgeENBConfigurationTransferIEFieldValueCodecFieldEncode(v *ENBConfigurationTransferIEFieldValueCodec) *func(ENBConfigurationTransferIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationTransferIEFieldValueCodecFieldPath(v *ENBConfigurationTransferIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationTransferIEFieldValueCodecMethodEncodeBudgetValue(v ENBConfigurationTransferIEFieldValueCodec, a0 ENBConfigurationTransferIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationTransferIEFieldValueCodecMethodEncodeChanged(v ENBConfigurationTransferIEFieldValueCodec, a0 ENBConfigurationTransferIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationTransferIEValueERABIEContainerListAPERValueFieldContext(v *ENBConfigurationTransferIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationTransferIEValueERABIEContainerListAPERValueFieldReceived(v *ENBConfigurationTransferIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationTransferIEValueERABIEContainerListAPERValueFieldReplay(v *ENBConfigurationTransferIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationTransferIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ENBConfigurationTransferIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationTransferIEValueERABIEContainerListValueCodecFieldCapture(v *ENBConfigurationTransferIEValueERABIEContainerListValueCodec) *func(ENBConfigurationTransferIEValueERABIEContainerList, aper.DecodeState) (ENBConfigurationTransferIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationTransferIEValueERABIEContainerListValueCodecFieldCompare(v *ENBConfigurationTransferIEValueERABIEContainerListValueCodec) *func(ENBConfigurationTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationTransferIEValueERABIEContainerListValueCodecFieldContext(v *ENBConfigurationTransferIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationTransferIEValueERABIEContainerListValueCodecFieldDecode(v *ENBConfigurationTransferIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationTransferIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeENBConfigurationTransferIEValueERABIEContainerListValueCodecFieldEncode(v *ENBConfigurationTransferIEValueERABIEContainerListValueCodec) *func(ENBConfigurationTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationTransferIEValueERABIEContainerListValueCodecFieldPath(v *ENBConfigurationTransferIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationTransferIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ENBConfigurationTransferIEValueERABIEContainerListValueCodec, a0 ENBConfigurationTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationTransferIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ENBConfigurationTransferIEValueERABIEContainerListValueCodec, a0 ENBConfigurationTransferIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationTransferIEValueFieldId(v *ENBConfigurationTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBConfigurationTransferIEValueFieldIsOpaque(v *ENBConfigurationTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBConfigurationTransferIEValueFieldOpaque(v *ENBConfigurationTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeENBConfigurationTransferIEValueFieldReceived(v *ENBConfigurationTransferIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationTransferIEValueFieldReplay(v *ENBConfigurationTransferIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationTransferIEValueFieldRowENDCSONConfigurationTransferECT(v *ENBConfigurationTransferIEValue) **ENDCSONConfigurationTransfer {
	return &v.rowENDCSONConfigurationTransferECT
}
func BridgeENBConfigurationTransferIEValueFieldRowIntersystemSONConfigurationTransferECT(v *ENBConfigurationTransferIEValue) **s00.IntersystemSONConfigurationTransfer {
	return &v.rowIntersystemSONConfigurationTransferECT
}
func BridgeENBConfigurationTransferIEValueFieldRowSONConfigurationTransferECT(v *ENBConfigurationTransferIEValue) **SONConfigurationTransfer {
	return &v.rowSONConfigurationTransferECT
}
func BridgeENBConfigurationTransferIEValueMethodCaptureSemantics(v ENBConfigurationTransferIEValue, a0 aper.SemanticCapture) ENBConfigurationTransferIEValue {
	return v.captureSemantics(a0)
}
func BridgeENBConfigurationTransferIEValueMethodCompareSemantics(v ENBConfigurationTransferIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeENBConfigurationTransferIEValueMethodDecode(v ENBConfigurationTransferIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ENBConfigurationTransferIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeENBConfigurationTransferIEValueMethodEncode(v ENBConfigurationTransferIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeENBConfigurationTransferIEValueMethodEncodeFresh(v ENBConfigurationTransferIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeENBConfigurationTransferIEValueMethodMatchesID(v ENBConfigurationTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBConfigurationTransferIEValueMethodReason(v ENBConfigurationTransferIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeENBConfigurationTransferIEValueMethodRule(v ENBConfigurationTransferIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ENBConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBConfigurationTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (ENBConfigurationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBConfigurationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationTransferIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(ENBConfigurationTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec, a0 ENBConfigurationTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ENBConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec, a0 ENBConfigurationTransferIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationTransferIEValueProtocolIEContainerListAPERValueFieldContext(v *ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationTransferIEValueProtocolIEContainerListAPERValueFieldReceived(v *ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENBConfigurationTransferIEValueProtocolIEContainerListAPERValueFieldReplay(v *ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENBConfigurationTransferIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ENBConfigurationTransferIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENBConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldCapture(v *ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec) *func(ENBConfigurationTransferIEValueProtocolIEContainerList, aper.DecodeState) (ENBConfigurationTransferIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldCompare(v *ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec) *func(ENBConfigurationTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldContext(v *ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldDecode(v *ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ENBConfigurationTransferIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeENBConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldEncode(v *ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec) *func(ENBConfigurationTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldPath(v *ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeENBConfigurationTransferIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec, a0 ENBConfigurationTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENBConfigurationTransferIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ENBConfigurationTransferIEValueProtocolIEContainerListValueCodec, a0 ENBConfigurationTransferIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeENBConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldCodec(v *ENBConfigurationTransferIntersystemSONConfigurationTransferIEBinding) *s01.IntersystemSONConfigurationTransferValueCodec {
	return &v.codec
}
func BridgeENBConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldGet(v *ENBConfigurationTransferIntersystemSONConfigurationTransferIEBinding) *func(*ENBConfigurationTransferIEValue) (*s00.IntersystemSONConfigurationTransfer, bool) {
	return &v.get
}
func BridgeENBConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldInfo(v *ENBConfigurationTransferIntersystemSONConfigurationTransferIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeENBConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldInject(v *ENBConfigurationTransferIntersystemSONConfigurationTransferIEBinding) *func(s00.IntersystemSONConfigurationTransfer) ENBConfigurationTransferIEValue {
	return &v.inject
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
func BridgeENDCSONConfigurationTransferAPERValueFieldContext(v *ENDCSONConfigurationTransferAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCSONConfigurationTransferAPERValueFieldReceived(v *ENDCSONConfigurationTransferAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeENDCSONConfigurationTransferAPERValueFieldReplay(v *ENDCSONConfigurationTransferAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCSONConfigurationTransferAPERValueFieldWithoutReplay(v *ENDCSONConfigurationTransferAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeENDCSONConfigurationTransferFieldExtCount(v *ENDCSONConfigurationTransfer) *int64 {
	return &v.extCount
}
func BridgeENDCSONConfigurationTransferFieldExtData(v *ENDCSONConfigurationTransfer) *[][]byte {
	return &v.extData
}
func BridgeENDCSONConfigurationTransferFieldExtOrigin(v *ENDCSONConfigurationTransfer) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeENDCSONConfigurationTransferFieldExtPresent(v *ENDCSONConfigurationTransfer) *[]bool {
	return &v.extPresent
}
func BridgeENDCSONConfigurationTransferFieldExtWire(v *ENDCSONConfigurationTransfer) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeENDCSONConfigurationTransferFieldIEExtensionsIndef(v *ENDCSONConfigurationTransfer) *bool {
	return &v.iEExtensionsIndef
}
func BridgeENDCSONConfigurationTransferFieldPerExtPadding(v *ENDCSONConfigurationTransfer) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeENDCSONConfigurationTransferFieldPerPadding(v *ENDCSONConfigurationTransfer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeENDCSONConfigurationTransferFieldReceived(v *ENDCSONConfigurationTransfer) *bool {
	return &v.received
}
func BridgeENDCSONConfigurationTransferFieldReceivedAbsolute(v *ENDCSONConfigurationTransfer) *bool {
	return &v.receivedAbsolute
}
func BridgeENDCSONConfigurationTransferFieldReceivedBytes(v *ENDCSONConfigurationTransfer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeENDCSONConfigurationTransferFieldReceivedLocation(v *ENDCSONConfigurationTransfer) *aper.Location {
	return &v.receivedLocation
}
func BridgeENDCSONConfigurationTransferFieldReplay(v *ENDCSONConfigurationTransfer) *aper.Snapshot {
	return &v.replay
}
func BridgeENDCSONConfigurationTransferFieldStream(v *ENDCSONConfigurationTransfer) *aper.WireSpan {
	return &v.stream
}
func BridgeENDCSONConfigurationTransferFieldWithoutReplay(v *ENDCSONConfigurationTransfer) *bool {
	return &v.withoutReplay
}
func BridgeENDCSONConfigurationTransferMethodMarshalAPERBudget(v *ENDCSONConfigurationTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeENDCSONConfigurationTransferMethodMarshalAPERBudgetValue(v *ENDCSONConfigurationTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeENDCSONConfigurationTransferMethodMarshalAPERChanged(v *ENDCSONConfigurationTransfer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeENDCSONConfigurationTransferMethodMarshalAPERChangedValue(v *ENDCSONConfigurationTransfer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeENDCSONConfigurationTransferMethodMarshalAPERLegacy(v *ENDCSONConfigurationTransfer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeENDCSONConfigurationTransferMethodMarshalAPERNewValue(v *ENDCSONConfigurationTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeENDCSONConfigurationTransferMethodMarshalAPERPlanned(v *ENDCSONConfigurationTransfer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeENDCSONConfigurationTransferMethodMarshalAPERTo(v *ENDCSONConfigurationTransfer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeENDCSONConfigurationTransferMethodUnmarshalAPERFrom(v *ENDCSONConfigurationTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeENDCSONConfigurationTransferMethodUnmarshalAPERLegacy(v *ENDCSONConfigurationTransfer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeENDCSONConfigurationTransferMethodUnmarshalAPERWithOptions(v *ENDCSONConfigurationTransfer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeENDCSONConfigurationTransferValueCodecFieldCapture(v *ENDCSONConfigurationTransferValueCodec) *func(ENDCSONConfigurationTransfer, aper.DecodeState) (ENDCSONConfigurationTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeENDCSONConfigurationTransferValueCodecFieldCompare(v *ENDCSONConfigurationTransferValueCodec) *func(ENDCSONConfigurationTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENDCSONConfigurationTransferValueCodecFieldContext(v *ENDCSONConfigurationTransferValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENDCSONConfigurationTransferValueCodecFieldDecode(v *ENDCSONConfigurationTransferValueCodec) *func([]byte, aper.DecodeState) (ENDCSONConfigurationTransfer, error) {
	return &v.decode
}
func BridgeENDCSONConfigurationTransferValueCodecFieldEncode(v *ENDCSONConfigurationTransferValueCodec) *func(ENDCSONConfigurationTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENDCSONConfigurationTransferValueCodecFieldPath(v *ENDCSONConfigurationTransferValueCodec) *aper.Path {
	return &v.path
}
func BridgeENDCSONConfigurationTransferValueCodecMethodEncodeBudgetValue(v ENDCSONConfigurationTransferValueCodec, a0 ENDCSONConfigurationTransfer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeENDCSONConfigurationTransferValueCodecMethodEncodeChanged(v ENDCSONConfigurationTransferValueCodec, a0 ENDCSONConfigurationTransfer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeERABModificationConfirmSuccessfulBindingFieldCapture(v *ERABModificationConfirmSuccessfulBinding) *func(s40.ERABModificationConfirm, aper.DecodeState) (s40.ERABModificationConfirm, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModificationConfirmSuccessfulBindingFieldCompare(v *ERABModificationConfirmSuccessfulBinding) *func(s40.ERABModificationConfirm, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModificationConfirmSuccessfulBindingFieldContext(v *ERABModificationConfirmSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationConfirmSuccessfulBindingFieldDecode(v *ERABModificationConfirmSuccessfulBinding) *func([]byte, aper.DecodeState) (s40.ERABModificationConfirm, error) {
	return &v.decode
}
func BridgeERABModificationConfirmSuccessfulBindingFieldEncode(v *ERABModificationConfirmSuccessfulBinding) *func(*s40.ERABModificationConfirm, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModificationConfirmSuccessfulBindingFieldInfo(v *ERABModificationConfirmSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeERABModificationConfirmSuccessfulBindingFieldInject(v *ERABModificationConfirmSuccessfulBinding) *func(s40.ERABModificationConfirm) SuccessfulValue {
	return &v.inject
}
func BridgeERABModificationConfirmSuccessfulBindingFieldValidate(v *ERABModificationConfirmSuccessfulBinding) *func(*s40.ERABModificationConfirm, *aper.DecodeBudget) (s21.ValidationReport, error) {
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
func BridgeERABSetupResponseSuccessfulBindingFieldCapture(v *ERABSetupResponseSuccessfulBinding) *func(s47.ERABSetupResponse, aper.DecodeState) (s47.ERABSetupResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupResponseSuccessfulBindingFieldCompare(v *ERABSetupResponseSuccessfulBinding) *func(s47.ERABSetupResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupResponseSuccessfulBindingFieldContext(v *ERABSetupResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseSuccessfulBindingFieldDecode(v *ERABSetupResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s47.ERABSetupResponse, error) {
	return &v.decode
}
func BridgeERABSetupResponseSuccessfulBindingFieldEncode(v *ERABSetupResponseSuccessfulBinding) *func(*s47.ERABSetupResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupResponseSuccessfulBindingFieldInfo(v *ERABSetupResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeERABSetupResponseSuccessfulBindingFieldInject(v *ERABSetupResponseSuccessfulBinding) *func(s47.ERABSetupResponse) SuccessfulValue {
	return &v.inject
}
func BridgeERABSetupResponseSuccessfulBindingFieldValidate(v *ERABSetupResponseSuccessfulBinding) *func(*s47.ERABSetupResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
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
func BridgeHandoverCommandSuccessfulBindingFieldCapture(v *HandoverCommandSuccessfulBinding) *func(s41.HandoverCommand, aper.DecodeState) (s41.HandoverCommand, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCommandSuccessfulBindingFieldCompare(v *HandoverCommandSuccessfulBinding) *func(s41.HandoverCommand, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCommandSuccessfulBindingFieldContext(v *HandoverCommandSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCommandSuccessfulBindingFieldDecode(v *HandoverCommandSuccessfulBinding) *func([]byte, aper.DecodeState) (s41.HandoverCommand, error) {
	return &v.decode
}
func BridgeHandoverCommandSuccessfulBindingFieldEncode(v *HandoverCommandSuccessfulBinding) *func(*s41.HandoverCommand, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCommandSuccessfulBindingFieldInfo(v *HandoverCommandSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeHandoverCommandSuccessfulBindingFieldInject(v *HandoverCommandSuccessfulBinding) *func(s41.HandoverCommand) SuccessfulValue {
	return &v.inject
}
func BridgeHandoverCommandSuccessfulBindingFieldValidate(v *HandoverCommandSuccessfulBinding) *func(*s41.HandoverCommand, *aper.DecodeBudget) (s21.ValidationReport, error) {
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
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldCapture(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func(s48.PathSwitchRequestAcknowledge, aper.DecodeState) (s48.PathSwitchRequestAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldCompare(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func(s48.PathSwitchRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldContext(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldDecode(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func([]byte, aper.DecodeState) (s48.PathSwitchRequestAcknowledge, error) {
	return &v.decode
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldEncode(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func(*s48.PathSwitchRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldInfo(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldInject(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func(s48.PathSwitchRequestAcknowledge) SuccessfulValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldValidate(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func(*s48.PathSwitchRequestAcknowledge, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeResetAcknowledgeSuccessfulBindingFieldCapture(v *ResetAcknowledgeSuccessfulBinding) *func(s45.ResetAcknowledge, aper.DecodeState) (s45.ResetAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeResetAcknowledgeSuccessfulBindingFieldCompare(v *ResetAcknowledgeSuccessfulBinding) *func(s45.ResetAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetAcknowledgeSuccessfulBindingFieldContext(v *ResetAcknowledgeSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeSuccessfulBindingFieldDecode(v *ResetAcknowledgeSuccessfulBinding) *func([]byte, aper.DecodeState) (s45.ResetAcknowledge, error) {
	return &v.decode
}
func BridgeResetAcknowledgeSuccessfulBindingFieldEncode(v *ResetAcknowledgeSuccessfulBinding) *func(*s45.ResetAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetAcknowledgeSuccessfulBindingFieldInfo(v *ResetAcknowledgeSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeResetAcknowledgeSuccessfulBindingFieldInject(v *ResetAcknowledgeSuccessfulBinding) *func(s45.ResetAcknowledge) SuccessfulValue {
	return &v.inject
}
func BridgeResetAcknowledgeSuccessfulBindingFieldValidate(v *ResetAcknowledgeSuccessfulBinding) *func(*s45.ResetAcknowledge, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeS1RemovalResponseSuccessfulBindingFieldCapture(v *S1RemovalResponseSuccessfulBinding) *func(s27.S1RemovalResponse, aper.DecodeState) (s27.S1RemovalResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalResponseSuccessfulBindingFieldCompare(v *S1RemovalResponseSuccessfulBinding) *func(s27.S1RemovalResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalResponseSuccessfulBindingFieldContext(v *S1RemovalResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalResponseSuccessfulBindingFieldDecode(v *S1RemovalResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s27.S1RemovalResponse, error) {
	return &v.decode
}
func BridgeS1RemovalResponseSuccessfulBindingFieldEncode(v *S1RemovalResponseSuccessfulBinding) *func(*s27.S1RemovalResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalResponseSuccessfulBindingFieldInfo(v *S1RemovalResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1RemovalResponseSuccessfulBindingFieldInject(v *S1RemovalResponseSuccessfulBinding) *func(s27.S1RemovalResponse) SuccessfulValue {
	return &v.inject
}
func BridgeS1RemovalResponseSuccessfulBindingFieldValidate(v *S1RemovalResponseSuccessfulBinding) *func(*s27.S1RemovalResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeS1SetupResponseSuccessfulBindingFieldCapture(v *S1SetupResponseSuccessfulBinding) *func(s44.S1SetupResponse, aper.DecodeState) (s44.S1SetupResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupResponseSuccessfulBindingFieldCompare(v *S1SetupResponseSuccessfulBinding) *func(s44.S1SetupResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupResponseSuccessfulBindingFieldContext(v *S1SetupResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupResponseSuccessfulBindingFieldDecode(v *S1SetupResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s44.S1SetupResponse, error) {
	return &v.decode
}
func BridgeS1SetupResponseSuccessfulBindingFieldEncode(v *S1SetupResponseSuccessfulBinding) *func(*s44.S1SetupResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupResponseSuccessfulBindingFieldInfo(v *S1SetupResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1SetupResponseSuccessfulBindingFieldInject(v *S1SetupResponseSuccessfulBinding) *func(s44.S1SetupResponse) SuccessfulValue {
	return &v.inject
}
func BridgeS1SetupResponseSuccessfulBindingFieldValidate(v *S1SetupResponseSuccessfulBinding) *func(*s44.S1SetupResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeSONConfigurationTransferExtIETableMethodInfoRequestedTNLInfo(v SONConfigurationTransferExtIETable) s00.ExtensionInfo {
	return v.infoRequestedTNLInfo()
}
func BridgeSONConfigurationTransferExtIETableMethodInfoSynchronisationInformation(v SONConfigurationTransferExtIETable) s00.ExtensionInfo {
	return v.infoSynchronisationInformation()
}
func BridgeSONConfigurationTransferExtIETableMethodInfoX2TNLConfigurationInfo(v SONConfigurationTransferExtIETable) s00.ExtensionInfo {
	return v.infoX2TNLConfigurationInfo()
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
func BridgeSONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBindingFieldCodec(v *SONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBinding) *X2TNLConfigurationInfoValueCodec {
	return &v.codec
}
func BridgeSONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBindingFieldGet(v *SONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBinding) *func(*SONConfigurationTransferExtIEsValue) (*X2TNLConfigurationInfo, bool) {
	return &v.get
}
func BridgeSONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBindingFieldInfo(v *SONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBinding) *s00.ExtensionInfo {
	return &v.info
}
func BridgeSONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBindingFieldInject(v *SONConfigurationTransferExtIEsX2TNLConfigurationInfoExtBinding) *func(X2TNLConfigurationInfo) SONConfigurationTransferExtIEsValue {
	return &v.inject
}
func BridgeSONConfigurationTransferFieldExtCount(v *SONConfigurationTransfer) *int64 {
	return &v.extCount
}
func BridgeSONConfigurationTransferFieldExtData(v *SONConfigurationTransfer) *[][]byte {
	return &v.extData
}
func BridgeSONConfigurationTransferFieldExtOrigin(v *SONConfigurationTransfer) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSONConfigurationTransferFieldExtPresent(v *SONConfigurationTransfer) *[]bool {
	return &v.extPresent
}
func BridgeSONConfigurationTransferFieldExtWire(v *SONConfigurationTransfer) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeSONConfigurationTransferFieldIEExtensionsIndef(v *SONConfigurationTransfer) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSONConfigurationTransferFieldPerExtPadding(v *SONConfigurationTransfer) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSONConfigurationTransferFieldPerPadding(v *SONConfigurationTransfer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSONConfigurationTransferFieldReceived(v *SONConfigurationTransfer) *bool {
	return &v.received
}
func BridgeSONConfigurationTransferFieldReceivedAbsolute(v *SONConfigurationTransfer) *bool {
	return &v.receivedAbsolute
}
func BridgeSONConfigurationTransferFieldReceivedBytes(v *SONConfigurationTransfer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSONConfigurationTransferFieldReceivedLocation(v *SONConfigurationTransfer) *aper.Location {
	return &v.receivedLocation
}
func BridgeSONConfigurationTransferFieldReplay(v *SONConfigurationTransfer) *aper.Snapshot {
	return &v.replay
}
func BridgeSONConfigurationTransferFieldStream(v *SONConfigurationTransfer) *aper.WireSpan {
	return &v.stream
}
func BridgeSONConfigurationTransferFieldWithoutReplay(v *SONConfigurationTransfer) *bool {
	return &v.withoutReplay
}
func BridgeSONConfigurationTransferMethodMarshalAPERBudget(v *SONConfigurationTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSONConfigurationTransferMethodMarshalAPERBudgetValue(v *SONConfigurationTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSONConfigurationTransferMethodMarshalAPERChanged(v *SONConfigurationTransfer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSONConfigurationTransferMethodMarshalAPERChangedValue(v *SONConfigurationTransfer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSONConfigurationTransferMethodMarshalAPERLegacy(v *SONConfigurationTransfer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSONConfigurationTransferMethodMarshalAPERNewValue(v *SONConfigurationTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSONConfigurationTransferMethodMarshalAPERPlanned(v *SONConfigurationTransfer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSONConfigurationTransferMethodMarshalAPERTo(v *SONConfigurationTransfer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSONConfigurationTransferMethodUnmarshalAPERFrom(v *SONConfigurationTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSONConfigurationTransferMethodUnmarshalAPERLegacy(v *SONConfigurationTransfer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSONConfigurationTransferMethodUnmarshalAPERWithOptions(v *SONConfigurationTransfer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSONInformationAPERValueFieldContext(v *SONInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationAPERValueFieldReceived(v *SONInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONInformationAPERValueFieldReplay(v *SONInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationAPERValueFieldWithoutReplay(v *SONInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSONInformationFieldPerOpenTypePadding(v *SONInformation) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeSONInformationFieldPerPadding(v *SONInformation) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSONInformationFieldReceived(v *SONInformation) *bool         { return &v.received }
func BridgeSONInformationFieldReceivedAbsolute(v *SONInformation) *bool { return &v.receivedAbsolute }
func BridgeSONInformationFieldReceivedBytes(v *SONInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSONInformationFieldReceivedLocation(v *SONInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeSONInformationFieldReplay(v *SONInformation) *aper.Snapshot { return &v.replay }
func BridgeSONInformationFieldStream(v *SONInformation) *aper.WireSpan { return &v.stream }
func BridgeSONInformationFieldWithoutReplay(v *SONInformation) *bool   { return &v.withoutReplay }
func BridgeSONInformationMethodMarshalAPERBudget(v *SONInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSONInformationMethodMarshalAPERBudgetValue(v *SONInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeSONInformationMethodMarshalAPERChanged(v *SONInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSONInformationMethodMarshalAPERChangedValue(v *SONInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSONInformationMethodMarshalAPERLegacy(v *SONInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSONInformationMethodMarshalAPERNewValue(v *SONInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeSONInformationMethodMarshalAPERPlanned(v *SONInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeSONInformationMethodMarshalAPERTo(v *SONInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSONInformationMethodUnmarshalAPERFrom(v *SONInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSONInformationMethodUnmarshalAPERLegacy(v *SONInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSONInformationMethodUnmarshalAPERWithOptions(v *SONInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSONInformationReplyAPERValueFieldContext(v *SONInformationReplyAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationReplyAPERValueFieldReceived(v *SONInformationReplyAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSONInformationReplyAPERValueFieldReplay(v *SONInformationReplyAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSONInformationReplyAPERValueFieldWithoutReplay(v *SONInformationReplyAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeSONInformationReplyValueCodecFieldCapture(v *SONInformationReplyValueCodec) *func(SONInformationReply, aper.DecodeState) (SONInformationReply, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationReplyValueCodecFieldCompare(v *SONInformationReplyValueCodec) *func(SONInformationReply, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationReplyValueCodecFieldContext(v *SONInformationReplyValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationReplyValueCodecFieldDecode(v *SONInformationReplyValueCodec) *func([]byte, aper.DecodeState) (SONInformationReply, error) {
	return &v.decode
}
func BridgeSONInformationReplyValueCodecFieldEncode(v *SONInformationReplyValueCodec) *func(SONInformationReply, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationReplyValueCodecFieldPath(v *SONInformationReplyValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationReplyValueCodecMethodEncodeBudgetValue(v SONInformationReplyValueCodec, a0 SONInformationReply, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONInformationReplyValueCodecMethodEncodeChanged(v SONInformationReplyValueCodec, a0 SONInformationReply, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSONInformationValueCodecFieldCapture(v *SONInformationValueCodec) *func(SONInformation, aper.DecodeState) (SONInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationValueCodecFieldCompare(v *SONInformationValueCodec) *func(SONInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationValueCodecFieldContext(v *SONInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationValueCodecFieldDecode(v *SONInformationValueCodec) *func([]byte, aper.DecodeState) (SONInformation, error) {
	return &v.decode
}
func BridgeSONInformationValueCodecFieldEncode(v *SONInformationValueCodec) *func(SONInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationValueCodecFieldPath(v *SONInformationValueCodec) *aper.Path { return &v.path }
func BridgeSONInformationValueCodecMethodEncodeBudgetValue(v SONInformationValueCodec, a0 SONInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeSONInformationValueCodecMethodEncodeChanged(v SONInformationValueCodec, a0 SONInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
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
func BridgeSuccessfulValueFieldBodyERABModificationConfirm(v *SuccessfulValue) **s40.ERABModificationConfirm {
	return &v.bodyERABModificationConfirm
}
func BridgeSuccessfulValueFieldBodyERABModifyResponse(v *SuccessfulValue) **s46.ERABModifyResponse {
	return &v.bodyERABModifyResponse
}
func BridgeSuccessfulValueFieldBodyERABReleaseResponse(v *SuccessfulValue) **s46.ERABReleaseResponse {
	return &v.bodyERABReleaseResponse
}
func BridgeSuccessfulValueFieldBodyERABSetupResponse(v *SuccessfulValue) **s47.ERABSetupResponse {
	return &v.bodyERABSetupResponse
}
func BridgeSuccessfulValueFieldBodyHandoverCancelAcknowledge(v *SuccessfulValue) **s25.HandoverCancelAcknowledge {
	return &v.bodyHandoverCancelAcknowledge
}
func BridgeSuccessfulValueFieldBodyHandoverCommand(v *SuccessfulValue) **s41.HandoverCommand {
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
func BridgeSuccessfulValueFieldBodyPathSwitchRequestAcknowledge(v *SuccessfulValue) **s48.PathSwitchRequestAcknowledge {
	return &v.bodyPathSwitchRequestAcknowledge
}
func BridgeSuccessfulValueFieldBodyResetAcknowledge(v *SuccessfulValue) **s45.ResetAcknowledge {
	return &v.bodyResetAcknowledge
}
func BridgeSuccessfulValueFieldBodyS1RemovalResponse(v *SuccessfulValue) **s27.S1RemovalResponse {
	return &v.bodyS1RemovalResponse
}
func BridgeSuccessfulValueFieldBodyS1SetupResponse(v *SuccessfulValue) **s44.S1SetupResponse {
	return &v.bodyS1SetupResponse
}
func BridgeSuccessfulValueFieldBodyUEContextModificationConfirm(v *SuccessfulValue) **s36.UEContextModificationConfirm {
	return &v.bodyUEContextModificationConfirm
}
func BridgeSuccessfulValueFieldBodyUEContextModificationResponse(v *SuccessfulValue) **s37.UEContextModificationResponse {
	return &v.bodyUEContextModificationResponse
}
func BridgeSuccessfulValueFieldBodyUEContextReleaseComplete(v *SuccessfulValue) **s47.UEContextReleaseComplete {
	return &v.bodyUEContextReleaseComplete
}
func BridgeSuccessfulValueFieldBodyUEContextResumeResponse(v *SuccessfulValue) **s39.UEContextResumeResponse {
	return &v.bodyUEContextResumeResponse
}
func BridgeSuccessfulValueFieldBodyUEContextSuspendResponse(v *SuccessfulValue) **s37.UEContextSuspendResponse {
	return &v.bodyUEContextSuspendResponse
}
func BridgeSuccessfulValueFieldBodyUERadioCapabilityIDMappingResponse(v *SuccessfulValue) **s37.UERadioCapabilityIDMappingResponse {
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
func BridgeUEContextModificationResponseSuccessfulBindingFieldCapture(v *UEContextModificationResponseSuccessfulBinding) *func(s37.UEContextModificationResponse, aper.DecodeState) (s37.UEContextModificationResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldCompare(v *UEContextModificationResponseSuccessfulBinding) *func(s37.UEContextModificationResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldContext(v *UEContextModificationResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldDecode(v *UEContextModificationResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s37.UEContextModificationResponse, error) {
	return &v.decode
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldEncode(v *UEContextModificationResponseSuccessfulBinding) *func(*s37.UEContextModificationResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldInfo(v *UEContextModificationResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldInject(v *UEContextModificationResponseSuccessfulBinding) *func(s37.UEContextModificationResponse) SuccessfulValue {
	return &v.inject
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldValidate(v *UEContextModificationResponseSuccessfulBinding) *func(*s37.UEContextModificationResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldCapture(v *UEContextReleaseCompleteSuccessfulBinding) *func(s47.UEContextReleaseComplete, aper.DecodeState) (s47.UEContextReleaseComplete, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldCompare(v *UEContextReleaseCompleteSuccessfulBinding) *func(s47.UEContextReleaseComplete, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldContext(v *UEContextReleaseCompleteSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldDecode(v *UEContextReleaseCompleteSuccessfulBinding) *func([]byte, aper.DecodeState) (s47.UEContextReleaseComplete, error) {
	return &v.decode
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldEncode(v *UEContextReleaseCompleteSuccessfulBinding) *func(*s47.UEContextReleaseComplete, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldInfo(v *UEContextReleaseCompleteSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldInject(v *UEContextReleaseCompleteSuccessfulBinding) *func(s47.UEContextReleaseComplete) SuccessfulValue {
	return &v.inject
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldValidate(v *UEContextReleaseCompleteSuccessfulBinding) *func(*s47.UEContextReleaseComplete, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldCapture(v *UEContextResumeResponseSuccessfulBinding) *func(s39.UEContextResumeResponse, aper.DecodeState) (s39.UEContextResumeResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldCompare(v *UEContextResumeResponseSuccessfulBinding) *func(s39.UEContextResumeResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldContext(v *UEContextResumeResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldDecode(v *UEContextResumeResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s39.UEContextResumeResponse, error) {
	return &v.decode
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldEncode(v *UEContextResumeResponseSuccessfulBinding) *func(*s39.UEContextResumeResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldInfo(v *UEContextResumeResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldInject(v *UEContextResumeResponseSuccessfulBinding) *func(s39.UEContextResumeResponse) SuccessfulValue {
	return &v.inject
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldValidate(v *UEContextResumeResponseSuccessfulBinding) *func(*s39.UEContextResumeResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldCapture(v *UEContextSuspendResponseSuccessfulBinding) *func(s37.UEContextSuspendResponse, aper.DecodeState) (s37.UEContextSuspendResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldCompare(v *UEContextSuspendResponseSuccessfulBinding) *func(s37.UEContextSuspendResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldContext(v *UEContextSuspendResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldDecode(v *UEContextSuspendResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s37.UEContextSuspendResponse, error) {
	return &v.decode
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldEncode(v *UEContextSuspendResponseSuccessfulBinding) *func(*s37.UEContextSuspendResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldInfo(v *UEContextSuspendResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldInject(v *UEContextSuspendResponseSuccessfulBinding) *func(s37.UEContextSuspendResponse) SuccessfulValue {
	return &v.inject
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldValidate(v *UEContextSuspendResponseSuccessfulBinding) *func(*s37.UEContextSuspendResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldCapture(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func(s37.UERadioCapabilityIDMappingResponse, aper.DecodeState) (s37.UERadioCapabilityIDMappingResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldCompare(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func(s37.UERadioCapabilityIDMappingResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldContext(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldDecode(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s37.UERadioCapabilityIDMappingResponse, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldEncode(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func(*s37.UERadioCapabilityIDMappingResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldInfo(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldInject(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func(s37.UERadioCapabilityIDMappingResponse) SuccessfulValue {
	return &v.inject
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldValidate(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func(*s37.UERadioCapabilityIDMappingResponse, *aper.DecodeBudget) (s21.ValidationReport, error) {
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
func BridgeX2TNLConfigurationInfoAPERValueFieldContext(v *X2TNLConfigurationInfoAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeX2TNLConfigurationInfoAPERValueFieldReceived(v *X2TNLConfigurationInfoAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeX2TNLConfigurationInfoAPERValueFieldReplay(v *X2TNLConfigurationInfoAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeX2TNLConfigurationInfoAPERValueFieldWithoutReplay(v *X2TNLConfigurationInfoAPERValue) *bool {
	return &v.withoutReplay
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
func BridgeX2TNLConfigurationInfoValueCodecFieldCapture(v *X2TNLConfigurationInfoValueCodec) *func(X2TNLConfigurationInfo, aper.DecodeState) (X2TNLConfigurationInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeX2TNLConfigurationInfoValueCodecFieldCompare(v *X2TNLConfigurationInfoValueCodec) *func(X2TNLConfigurationInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeX2TNLConfigurationInfoValueCodecFieldContext(v *X2TNLConfigurationInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeX2TNLConfigurationInfoValueCodecFieldDecode(v *X2TNLConfigurationInfoValueCodec) *func([]byte, aper.DecodeState) (X2TNLConfigurationInfo, error) {
	return &v.decode
}
func BridgeX2TNLConfigurationInfoValueCodecFieldEncode(v *X2TNLConfigurationInfoValueCodec) *func(X2TNLConfigurationInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeX2TNLConfigurationInfoValueCodecFieldPath(v *X2TNLConfigurationInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeX2TNLConfigurationInfoValueCodecMethodEncodeBudgetValue(v X2TNLConfigurationInfoValueCodec, a0 X2TNLConfigurationInfo, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeX2TNLConfigurationInfoValueCodecMethodEncodeChanged(v X2TNLConfigurationInfoValueCodec, a0 X2TNLConfigurationInfo, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ENBConfigurationTransferIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 129:
		if value, ok := v.AsSONConfigurationTransferECT(); ok {
			return value, true
		}
	case 294:
		if value, ok := v.AsENDCSONConfigurationTransferECT(); ok {
			return value, true
		}
	case 310:
		if value, ok := v.AsIntersystemSONConfigurationTransferECT(); ok {
			return value, true
		}
	}
	return nil, false
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
