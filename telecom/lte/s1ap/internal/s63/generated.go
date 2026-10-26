// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s63 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s63

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
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
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	s53 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s53"
	s55 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s55"
	s56 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s56"
	s57 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s57"
	s58 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s58"
	s61 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s61"
	s62 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s62"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func NewHandoverRequired(fields s43.HandoverRequiredIEContainer, options ...aper.BuildOption) (s43.HandoverRequired, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s43.HandoverRequired{}, aper.OperationError(err, "HandoverRequired")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s43.HandoverRequiredIEField](bb, uint64(len(fields))); err != nil {
		return s43.HandoverRequired{}, aper.OperationError(err, "HandoverRequired")
	}
	v := s43.HandoverRequired{ProtocolIEs: make(s43.HandoverRequiredIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverRequiredBudget(&v, budget)
	if err != nil {
		return s43.HandoverRequired{}, aper.OperationError(err, "HandoverRequired")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s43.HandoverRequired{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "HandoverRequired")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s43.HandoverRequired{}, aper.OperationError(&s25.BuildError{Issues: issues}, "HandoverRequired")
	}
	if _, err := s43.BridgeHandoverRequiredMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s43.HandoverRequired{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverRequired.protocolIEs:", err), "HandoverRequired")
	}
	return v, aper.OperationError(nil, "HandoverRequired")
}
func NewHandoverNotify(fields s44.HandoverNotifyIEContainer, options ...aper.BuildOption) (s44.HandoverNotify, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s44.HandoverNotify{}, aper.OperationError(err, "HandoverNotify")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s44.HandoverNotifyIEField](bb, uint64(len(fields))); err != nil {
		return s44.HandoverNotify{}, aper.OperationError(err, "HandoverNotify")
	}
	v := s44.HandoverNotify{ProtocolIEs: make(s44.HandoverNotifyIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverNotifyBudget(&v, budget)
	if err != nil {
		return s44.HandoverNotify{}, aper.OperationError(err, "HandoverNotify")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s44.HandoverNotify{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "HandoverNotify")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s44.HandoverNotify{}, aper.OperationError(&s25.BuildError{Issues: issues}, "HandoverNotify")
	}
	if _, err := s44.BridgeHandoverNotifyMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s44.HandoverNotify{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverNotify.protocolIEs:", err), "HandoverNotify")
	}
	return v, aper.OperationError(nil, "HandoverNotify")
}
func NewPathSwitchRequest(fields s51.PathSwitchRequestIEContainer, options ...aper.BuildOption) (s51.PathSwitchRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.PathSwitchRequest{}, aper.OperationError(err, "PathSwitchRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s51.PathSwitchRequestIEField](bb, uint64(len(fields))); err != nil {
		return s51.PathSwitchRequest{}, aper.OperationError(err, "PathSwitchRequest")
	}
	v := s51.PathSwitchRequest{ProtocolIEs: make(s51.PathSwitchRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidatePathSwitchRequestBudget(&v, budget)
	if err != nil {
		return s51.PathSwitchRequest{}, aper.OperationError(err, "PathSwitchRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s51.PathSwitchRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "PathSwitchRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.PathSwitchRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "PathSwitchRequest")
	}
	if _, err := s51.BridgePathSwitchRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s51.PathSwitchRequest{}, aper.OperationError(fmt.Errorf("%s %w", "PathSwitchRequest.protocolIEs:", err), "PathSwitchRequest")
	}
	return v, aper.OperationError(nil, "PathSwitchRequest")
}
func NewPathSwitchRequestAcknowledge(fields s58.PathSwitchRequestAcknowledgeIEContainer, options ...aper.BuildOption) (s58.PathSwitchRequestAcknowledge, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s58.PathSwitchRequestAcknowledge{}, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s58.PathSwitchRequestAcknowledgeIEField](bb, uint64(len(fields))); err != nil {
		return s58.PathSwitchRequestAcknowledge{}, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	v := s58.PathSwitchRequestAcknowledge{ProtocolIEs: make(s58.PathSwitchRequestAcknowledgeIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidatePathSwitchRequestAcknowledgeBudget(&v, budget)
	if err != nil {
		return s58.PathSwitchRequestAcknowledge{}, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s58.PathSwitchRequestAcknowledge{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "PathSwitchRequestAcknowledge")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s58.PathSwitchRequestAcknowledge{}, aper.OperationError(&s25.BuildError{Issues: issues}, "PathSwitchRequestAcknowledge")
	}
	if _, err := s58.BridgePathSwitchRequestAcknowledgeMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s58.PathSwitchRequestAcknowledge{}, aper.OperationError(fmt.Errorf("%s %w", "PathSwitchRequestAcknowledge.protocolIEs:", err), "PathSwitchRequestAcknowledge")
	}
	return v, aper.OperationError(nil, "PathSwitchRequestAcknowledge")
}
func NewERABSetupRequest(fields s51.ERABSetupRequestIEContainer, options ...aper.BuildOption) (s51.ERABSetupRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.ERABSetupRequest{}, aper.OperationError(err, "ERABSetupRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s51.ERABSetupRequestIEField](bb, uint64(len(fields))); err != nil {
		return s51.ERABSetupRequest{}, aper.OperationError(err, "ERABSetupRequest")
	}
	v := s51.ERABSetupRequest{ProtocolIEs: make(s51.ERABSetupRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABSetupRequestBudget(&v, budget)
	if err != nil {
		return s51.ERABSetupRequest{}, aper.OperationError(err, "ERABSetupRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s51.ERABSetupRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ERABSetupRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.ERABSetupRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ERABSetupRequest")
	}
	if _, err := s51.BridgeERABSetupRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s51.ERABSetupRequest{}, aper.OperationError(fmt.Errorf("%s %w", "ERABSetupRequest.protocolIEs:", err), "ERABSetupRequest")
	}
	return v, aper.OperationError(nil, "ERABSetupRequest")
}
func NewERABSetupResponse(fields s56.ERABSetupResponseIEContainer, options ...aper.BuildOption) (s57.ERABSetupResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s57.ERABSetupResponse{}, aper.OperationError(err, "ERABSetupResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s56.ERABSetupResponseIEField](bb, uint64(len(fields))); err != nil {
		return s57.ERABSetupResponse{}, aper.OperationError(err, "ERABSetupResponse")
	}
	v := s57.ERABSetupResponse{ProtocolIEs: make(s56.ERABSetupResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABSetupResponseBudget(&v, budget)
	if err != nil {
		return s57.ERABSetupResponse{}, aper.OperationError(err, "ERABSetupResponse")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s57.ERABSetupResponse{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ERABSetupResponse")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s57.ERABSetupResponse{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ERABSetupResponse")
	}
	if _, err := s57.BridgeERABSetupResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s57.ERABSetupResponse{}, aper.OperationError(fmt.Errorf("%s %w", "ERABSetupResponse.protocolIEs:", err), "ERABSetupResponse")
	}
	return v, aper.OperationError(nil, "ERABSetupResponse")
}
func NewERABModifyRequest(fields s50.ERABModifyRequestIEContainer, options ...aper.BuildOption) (s51.ERABModifyRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s51.ERABModifyRequest{}, aper.OperationError(err, "ERABModifyRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s50.ERABModifyRequestIEField](bb, uint64(len(fields))); err != nil {
		return s51.ERABModifyRequest{}, aper.OperationError(err, "ERABModifyRequest")
	}
	v := s51.ERABModifyRequest{ProtocolIEs: make(s50.ERABModifyRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABModifyRequestBudget(&v, budget)
	if err != nil {
		return s51.ERABModifyRequest{}, aper.OperationError(err, "ERABModifyRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s51.ERABModifyRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ERABModifyRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s51.ERABModifyRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ERABModifyRequest")
	}
	if _, err := s51.BridgeERABModifyRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s51.ERABModifyRequest{}, aper.OperationError(fmt.Errorf("%s %w", "ERABModifyRequest.protocolIEs:", err), "ERABModifyRequest")
	}
	return v, aper.OperationError(nil, "ERABModifyRequest")
}
func NewERABModifyResponse(fields s56.ERABModifyResponseIEContainer, options ...aper.BuildOption) (s57.ERABModifyResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s57.ERABModifyResponse{}, aper.OperationError(err, "ERABModifyResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s56.ERABModifyResponseIEField](bb, uint64(len(fields))); err != nil {
		return s57.ERABModifyResponse{}, aper.OperationError(err, "ERABModifyResponse")
	}
	v := s57.ERABModifyResponse{ProtocolIEs: make(s56.ERABModifyResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABModifyResponseBudget(&v, budget)
	if err != nil {
		return s57.ERABModifyResponse{}, aper.OperationError(err, "ERABModifyResponse")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s57.ERABModifyResponse{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ERABModifyResponse")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s57.ERABModifyResponse{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ERABModifyResponse")
	}
	if _, err := s57.BridgeERABModifyResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s57.ERABModifyResponse{}, aper.OperationError(fmt.Errorf("%s %w", "ERABModifyResponse.protocolIEs:", err), "ERABModifyResponse")
	}
	return v, aper.OperationError(nil, "ERABModifyResponse")
}
func NewERABReleaseCommand(fields s49.ERABReleaseCommandIEContainer, options ...aper.BuildOption) (s49.ERABReleaseCommand, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s49.ERABReleaseCommand{}, aper.OperationError(err, "ERABReleaseCommand")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s49.ERABReleaseCommandIEField](bb, uint64(len(fields))); err != nil {
		return s49.ERABReleaseCommand{}, aper.OperationError(err, "ERABReleaseCommand")
	}
	v := s49.ERABReleaseCommand{ProtocolIEs: make(s49.ERABReleaseCommandIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABReleaseCommandBudget(&v, budget)
	if err != nil {
		return s49.ERABReleaseCommand{}, aper.OperationError(err, "ERABReleaseCommand")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s49.ERABReleaseCommand{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ERABReleaseCommand")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s49.ERABReleaseCommand{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ERABReleaseCommand")
	}
	if _, err := s49.BridgeERABReleaseCommandMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s49.ERABReleaseCommand{}, aper.OperationError(fmt.Errorf("%s %w", "ERABReleaseCommand.protocolIEs:", err), "ERABReleaseCommand")
	}
	return v, aper.OperationError(nil, "ERABReleaseCommand")
}
func NewERABReleaseResponse(fields s56.ERABReleaseResponseIEContainer, options ...aper.BuildOption) (s57.ERABReleaseResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s57.ERABReleaseResponse{}, aper.OperationError(err, "ERABReleaseResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s56.ERABReleaseResponseIEField](bb, uint64(len(fields))); err != nil {
		return s57.ERABReleaseResponse{}, aper.OperationError(err, "ERABReleaseResponse")
	}
	v := s57.ERABReleaseResponse{ProtocolIEs: make(s56.ERABReleaseResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABReleaseResponseBudget(&v, budget)
	if err != nil {
		return s57.ERABReleaseResponse{}, aper.OperationError(err, "ERABReleaseResponse")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s57.ERABReleaseResponse{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ERABReleaseResponse")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s57.ERABReleaseResponse{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ERABReleaseResponse")
	}
	if _, err := s57.BridgeERABReleaseResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s57.ERABReleaseResponse{}, aper.OperationError(fmt.Errorf("%s %w", "ERABReleaseResponse.protocolIEs:", err), "ERABReleaseResponse")
	}
	return v, aper.OperationError(nil, "ERABReleaseResponse")
}
func NewERABReleaseIndication(fields s56.ERABReleaseIndicationIEContainer, options ...aper.BuildOption) (s57.ERABReleaseIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s57.ERABReleaseIndication{}, aper.OperationError(err, "ERABReleaseIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s56.ERABReleaseIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s57.ERABReleaseIndication{}, aper.OperationError(err, "ERABReleaseIndication")
	}
	v := s57.ERABReleaseIndication{ProtocolIEs: make(s56.ERABReleaseIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABReleaseIndicationBudget(&v, budget)
	if err != nil {
		return s57.ERABReleaseIndication{}, aper.OperationError(err, "ERABReleaseIndication")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s57.ERABReleaseIndication{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ERABReleaseIndication")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s57.ERABReleaseIndication{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ERABReleaseIndication")
	}
	if _, err := s57.BridgeERABReleaseIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s57.ERABReleaseIndication{}, aper.OperationError(fmt.Errorf("%s %w", "ERABReleaseIndication.protocolIEs:", err), "ERABReleaseIndication")
	}
	return v, aper.OperationError(nil, "ERABReleaseIndication")
}
func NewInitialUEMessage(fields s44.InitialUEMessageIEContainer, options ...aper.BuildOption) (s45.InitialUEMessage, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s45.InitialUEMessage{}, aper.OperationError(err, "InitialUEMessage")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s44.InitialUEMessageIEField](bb, uint64(len(fields))); err != nil {
		return s45.InitialUEMessage{}, aper.OperationError(err, "InitialUEMessage")
	}
	v := s45.InitialUEMessage{ProtocolIEs: make(s44.InitialUEMessageIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateInitialUEMessageBudget(&v, budget)
	if err != nil {
		return s45.InitialUEMessage{}, aper.OperationError(err, "InitialUEMessage")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s45.InitialUEMessage{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "InitialUEMessage")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s45.InitialUEMessage{}, aper.OperationError(&s25.BuildError{Issues: issues}, "InitialUEMessage")
	}
	if _, err := s45.BridgeInitialUEMessageMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s45.InitialUEMessage{}, aper.OperationError(fmt.Errorf("%s %w", "InitialUEMessage.protocolIEs:", err), "InitialUEMessage")
	}
	return v, aper.OperationError(nil, "InitialUEMessage")
}
func NewUplinkNASTransport(fields s41.UplinkNASTransportIEContainer, options ...aper.BuildOption) (s55.UplinkNASTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s55.UplinkNASTransport{}, aper.OperationError(err, "UplinkNASTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s41.UplinkNASTransportIEField](bb, uint64(len(fields))); err != nil {
		return s55.UplinkNASTransport{}, aper.OperationError(err, "UplinkNASTransport")
	}
	v := s55.UplinkNASTransport{ProtocolIEs: make(s41.UplinkNASTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUplinkNASTransportBudget(&v, budget)
	if err != nil {
		return s55.UplinkNASTransport{}, aper.OperationError(err, "UplinkNASTransport")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s55.UplinkNASTransport{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UplinkNASTransport")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s55.UplinkNASTransport{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UplinkNASTransport")
	}
	if _, err := s55.BridgeUplinkNASTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s55.UplinkNASTransport{}, aper.OperationError(fmt.Errorf("%s %w", "UplinkNASTransport.protocolIEs:", err), "UplinkNASTransport")
	}
	return v, aper.OperationError(nil, "UplinkNASTransport")
}
func NewReset(fields s45.ResetIEContainer, options ...aper.BuildOption) (s45.Reset, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s45.Reset{}, aper.OperationError(err, "Reset")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s45.ResetIEField](bb, uint64(len(fields))); err != nil {
		return s45.Reset{}, aper.OperationError(err, "Reset")
	}
	v := s45.Reset{ProtocolIEs: make(s45.ResetIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateResetBudget(&v, budget)
	if err != nil {
		return s45.Reset{}, aper.OperationError(err, "Reset")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s45.Reset{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Reset")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s45.Reset{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Reset")
	}
	if _, err := s45.BridgeResetMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s45.Reset{}, aper.OperationError(fmt.Errorf("%s %w", "Reset.protocolIEs:", err), "Reset")
	}
	return v, aper.OperationError(nil, "Reset")
}
func NewResetAcknowledge(fields s55.ResetAcknowledgeIEContainer, options ...aper.BuildOption) (s55.ResetAcknowledge, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s55.ResetAcknowledge{}, aper.OperationError(err, "ResetAcknowledge")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s55.ResetAcknowledgeIEField](bb, uint64(len(fields))); err != nil {
		return s55.ResetAcknowledge{}, aper.OperationError(err, "ResetAcknowledge")
	}
	v := s55.ResetAcknowledge{ProtocolIEs: make(s55.ResetAcknowledgeIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateResetAcknowledgeBudget(&v, budget)
	if err != nil {
		return s55.ResetAcknowledge{}, aper.OperationError(err, "ResetAcknowledge")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s55.ResetAcknowledge{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ResetAcknowledge")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s55.ResetAcknowledge{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ResetAcknowledge")
	}
	if _, err := s55.BridgeResetAcknowledgeMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s55.ResetAcknowledge{}, aper.OperationError(fmt.Errorf("%s %w", "ResetAcknowledge.protocolIEs:", err), "ResetAcknowledge")
	}
	return v, aper.OperationError(nil, "ResetAcknowledge")
}
func NewUEContextReleaseRequest(fields s53.UEContextReleaseRequestIEContainer, options ...aper.BuildOption) (s53.UEContextReleaseRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s53.UEContextReleaseRequest{}, aper.OperationError(err, "UEContextReleaseRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s53.UEContextReleaseRequestIEField](bb, uint64(len(fields))); err != nil {
		return s53.UEContextReleaseRequest{}, aper.OperationError(err, "UEContextReleaseRequest")
	}
	v := s53.UEContextReleaseRequest{ProtocolIEs: make(s53.UEContextReleaseRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextReleaseRequestBudget(&v, budget)
	if err != nil {
		return s53.UEContextReleaseRequest{}, aper.OperationError(err, "UEContextReleaseRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s53.UEContextReleaseRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UEContextReleaseRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s53.UEContextReleaseRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UEContextReleaseRequest")
	}
	if _, err := s53.BridgeUEContextReleaseRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s53.UEContextReleaseRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextReleaseRequest.protocolIEs:", err), "UEContextReleaseRequest")
	}
	return v, aper.OperationError(nil, "UEContextReleaseRequest")
}
func NewUplinkS1cdma2000tunnelling(fields s24.UplinkS1cdma2000tunnellingIEContainer, options ...aper.BuildOption) (s55.UplinkS1cdma2000tunnelling, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s55.UplinkS1cdma2000tunnelling{}, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s24.UplinkS1cdma2000tunnellingIEField](bb, uint64(len(fields))); err != nil {
		return s55.UplinkS1cdma2000tunnelling{}, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	v := s55.UplinkS1cdma2000tunnelling{ProtocolIEs: make(s24.UplinkS1cdma2000tunnellingIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUplinkS1cdma2000tunnellingBudget(&v, budget)
	if err != nil {
		return s55.UplinkS1cdma2000tunnelling{}, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s55.UplinkS1cdma2000tunnelling{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UplinkS1cdma2000tunnelling")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s55.UplinkS1cdma2000tunnelling{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UplinkS1cdma2000tunnelling")
	}
	if _, err := s55.BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s55.UplinkS1cdma2000tunnelling{}, aper.OperationError(fmt.Errorf("%s %w", "UplinkS1cdma2000tunnelling.protocolIEs:", err), "UplinkS1cdma2000tunnelling")
	}
	return v, aper.OperationError(nil, "UplinkS1cdma2000tunnelling")
}
func NewUEContextModificationResponse(fields s27.UEContextModificationResponseIEContainer, options ...aper.BuildOption) (s46.UEContextModificationResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.UEContextModificationResponse{}, aper.OperationError(err, "UEContextModificationResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s27.UEContextModificationResponseIEField](bb, uint64(len(fields))); err != nil {
		return s46.UEContextModificationResponse{}, aper.OperationError(err, "UEContextModificationResponse")
	}
	v := s46.UEContextModificationResponse{ProtocolIEs: make(s27.UEContextModificationResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextModificationResponseBudget(&v, budget)
	if err != nil {
		return s46.UEContextModificationResponse{}, aper.OperationError(err, "UEContextModificationResponse")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s46.UEContextModificationResponse{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UEContextModificationResponse")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.UEContextModificationResponse{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UEContextModificationResponse")
	}
	if _, err := s46.BridgeUEContextModificationResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.UEContextModificationResponse{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextModificationResponse.protocolIEs:", err), "UEContextModificationResponse")
	}
	return v, aper.OperationError(nil, "UEContextModificationResponse")
}
func NewUEContextModificationFailure(fields s27.UEContextModificationFailureIEContainer, options ...aper.BuildOption) (s45.UEContextModificationFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s45.UEContextModificationFailure{}, aper.OperationError(err, "UEContextModificationFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s27.UEContextModificationFailureIEField](bb, uint64(len(fields))); err != nil {
		return s45.UEContextModificationFailure{}, aper.OperationError(err, "UEContextModificationFailure")
	}
	v := s45.UEContextModificationFailure{ProtocolIEs: make(s27.UEContextModificationFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextModificationFailureBudget(&v, budget)
	if err != nil {
		return s45.UEContextModificationFailure{}, aper.OperationError(err, "UEContextModificationFailure")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s45.UEContextModificationFailure{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UEContextModificationFailure")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s45.UEContextModificationFailure{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UEContextModificationFailure")
	}
	if _, err := s45.BridgeUEContextModificationFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s45.UEContextModificationFailure{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextModificationFailure.protocolIEs:", err), "UEContextModificationFailure")
	}
	return v, aper.OperationError(nil, "UEContextModificationFailure")
}
func NewUECapabilityInfoIndication(fields s14.UECapabilityInfoIndicationIEContainer, options ...aper.BuildOption) (s45.UECapabilityInfoIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s45.UECapabilityInfoIndication{}, aper.OperationError(err, "UECapabilityInfoIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s14.UECapabilityInfoIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s45.UECapabilityInfoIndication{}, aper.OperationError(err, "UECapabilityInfoIndication")
	}
	v := s45.UECapabilityInfoIndication{ProtocolIEs: make(s14.UECapabilityInfoIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUECapabilityInfoIndicationBudget(&v, budget)
	if err != nil {
		return s45.UECapabilityInfoIndication{}, aper.OperationError(err, "UECapabilityInfoIndication")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s45.UECapabilityInfoIndication{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UECapabilityInfoIndication")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s45.UECapabilityInfoIndication{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UECapabilityInfoIndication")
	}
	if _, err := s45.BridgeUECapabilityInfoIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s45.UECapabilityInfoIndication{}, aper.OperationError(fmt.Errorf("%s %w", "UECapabilityInfoIndication.protocolIEs:", err), "UECapabilityInfoIndication")
	}
	return v, aper.OperationError(nil, "UECapabilityInfoIndication")
}
func NewUEContextReleaseCommand(fields s46.UEContextReleaseCommandIEContainer, options ...aper.BuildOption) (s47.UEContextReleaseCommand, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s47.UEContextReleaseCommand{}, aper.OperationError(err, "UEContextReleaseCommand")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s46.UEContextReleaseCommandIEField](bb, uint64(len(fields))); err != nil {
		return s47.UEContextReleaseCommand{}, aper.OperationError(err, "UEContextReleaseCommand")
	}
	v := s47.UEContextReleaseCommand{ProtocolIEs: make(s46.UEContextReleaseCommandIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextReleaseCommandBudget(&v, budget)
	if err != nil {
		return s47.UEContextReleaseCommand{}, aper.OperationError(err, "UEContextReleaseCommand")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s47.UEContextReleaseCommand{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UEContextReleaseCommand")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s47.UEContextReleaseCommand{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UEContextReleaseCommand")
	}
	if _, err := s47.BridgeUEContextReleaseCommandMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s47.UEContextReleaseCommand{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextReleaseCommand.protocolIEs:", err), "UEContextReleaseCommand")
	}
	return v, aper.OperationError(nil, "UEContextReleaseCommand")
}
func NewUEContextReleaseComplete(fields s56.UEContextReleaseCompleteIEContainer, options ...aper.BuildOption) (s57.UEContextReleaseComplete, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s57.UEContextReleaseComplete{}, aper.OperationError(err, "UEContextReleaseComplete")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s56.UEContextReleaseCompleteIEField](bb, uint64(len(fields))); err != nil {
		return s57.UEContextReleaseComplete{}, aper.OperationError(err, "UEContextReleaseComplete")
	}
	v := s57.UEContextReleaseComplete{ProtocolIEs: make(s56.UEContextReleaseCompleteIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextReleaseCompleteBudget(&v, budget)
	if err != nil {
		return s57.UEContextReleaseComplete{}, aper.OperationError(err, "UEContextReleaseComplete")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s57.UEContextReleaseComplete{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UEContextReleaseComplete")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s57.UEContextReleaseComplete{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UEContextReleaseComplete")
	}
	if _, err := s57.BridgeUEContextReleaseCompleteMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s57.UEContextReleaseComplete{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextReleaseComplete.protocolIEs:", err), "UEContextReleaseComplete")
	}
	return v, aper.OperationError(nil, "UEContextReleaseComplete")
}
func NewTraceFailureIndication(fields s24.TraceFailureIndicationIEContainer, options ...aper.BuildOption) (s44.TraceFailureIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s44.TraceFailureIndication{}, aper.OperationError(err, "TraceFailureIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s24.TraceFailureIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s44.TraceFailureIndication{}, aper.OperationError(err, "TraceFailureIndication")
	}
	v := s44.TraceFailureIndication{ProtocolIEs: make(s24.TraceFailureIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateTraceFailureIndicationBudget(&v, budget)
	if err != nil {
		return s44.TraceFailureIndication{}, aper.OperationError(err, "TraceFailureIndication")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s44.TraceFailureIndication{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "TraceFailureIndication")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s44.TraceFailureIndication{}, aper.OperationError(&s25.BuildError{Issues: issues}, "TraceFailureIndication")
	}
	if _, err := s44.BridgeTraceFailureIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s44.TraceFailureIndication{}, aper.OperationError(fmt.Errorf("%s %w", "TraceFailureIndication.protocolIEs:", err), "TraceFailureIndication")
	}
	return v, aper.OperationError(nil, "TraceFailureIndication")
}
func NewENBDirectInformationTransfer(fields s43.ENBDirectInformationTransferIEContainer, options ...aper.BuildOption) (s43.ENBDirectInformationTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s43.ENBDirectInformationTransfer{}, aper.OperationError(err, "ENBDirectInformationTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s43.ENBDirectInformationTransferIEField](bb, uint64(len(fields))); err != nil {
		return s43.ENBDirectInformationTransfer{}, aper.OperationError(err, "ENBDirectInformationTransfer")
	}
	v := s43.ENBDirectInformationTransfer{ProtocolIEs: make(s43.ENBDirectInformationTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBDirectInformationTransferBudget(&v, budget)
	if err != nil {
		return s43.ENBDirectInformationTransfer{}, aper.OperationError(err, "ENBDirectInformationTransfer")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s43.ENBDirectInformationTransfer{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ENBDirectInformationTransfer")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s43.ENBDirectInformationTransfer{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ENBDirectInformationTransfer")
	}
	if _, err := s43.BridgeENBDirectInformationTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s43.ENBDirectInformationTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "ENBDirectInformationTransfer.protocolIEs:", err), "ENBDirectInformationTransfer")
	}
	return v, aper.OperationError(nil, "ENBDirectInformationTransfer")
}
func NewMMEDirectInformationTransfer(fields s43.MMEDirectInformationTransferIEContainer, options ...aper.BuildOption) (s43.MMEDirectInformationTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s43.MMEDirectInformationTransfer{}, aper.OperationError(err, "MMEDirectInformationTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s43.MMEDirectInformationTransferIEField](bb, uint64(len(fields))); err != nil {
		return s43.MMEDirectInformationTransfer{}, aper.OperationError(err, "MMEDirectInformationTransfer")
	}
	v := s43.MMEDirectInformationTransfer{ProtocolIEs: make(s43.MMEDirectInformationTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEDirectInformationTransferBudget(&v, budget)
	if err != nil {
		return s43.MMEDirectInformationTransfer{}, aper.OperationError(err, "MMEDirectInformationTransfer")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s43.MMEDirectInformationTransfer{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "MMEDirectInformationTransfer")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s43.MMEDirectInformationTransfer{}, aper.OperationError(&s25.BuildError{Issues: issues}, "MMEDirectInformationTransfer")
	}
	if _, err := s43.BridgeMMEDirectInformationTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s43.MMEDirectInformationTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "MMEDirectInformationTransfer.protocolIEs:", err), "MMEDirectInformationTransfer")
	}
	return v, aper.OperationError(nil, "MMEDirectInformationTransfer")
}
func NewKillResponse(fields s41.KillResponseIEContainer, options ...aper.BuildOption) (s42.KillResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s42.KillResponse{}, aper.OperationError(err, "KillResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s41.KillResponseIEField](bb, uint64(len(fields))); err != nil {
		return s42.KillResponse{}, aper.OperationError(err, "KillResponse")
	}
	v := s42.KillResponse{ProtocolIEs: make(s41.KillResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateKillResponseBudget(&v, budget)
	if err != nil {
		return s42.KillResponse{}, aper.OperationError(err, "KillResponse")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s42.KillResponse{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "KillResponse")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s42.KillResponse{}, aper.OperationError(&s25.BuildError{Issues: issues}, "KillResponse")
	}
	if _, err := s42.BridgeKillResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s42.KillResponse{}, aper.OperationError(fmt.Errorf("%s %w", "KillResponse.protocolIEs:", err), "KillResponse")
	}
	return v, aper.OperationError(nil, "KillResponse")
}
func NewUplinkUEAssociatedLPPaTransport(fields s14.UplinkUEAssociatedLPPaTransportIEContainer, options ...aper.BuildOption) (s55.UplinkUEAssociatedLPPaTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s55.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s14.UplinkUEAssociatedLPPaTransportIEField](bb, uint64(len(fields))); err != nil {
		return s55.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	v := s55.UplinkUEAssociatedLPPaTransport{ProtocolIEs: make(s14.UplinkUEAssociatedLPPaTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUplinkUEAssociatedLPPaTransportBudget(&v, budget)
	if err != nil {
		return s55.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s55.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UplinkUEAssociatedLPPaTransport")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s55.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UplinkUEAssociatedLPPaTransport")
	}
	if _, err := s55.BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s55.UplinkUEAssociatedLPPaTransport{}, aper.OperationError(fmt.Errorf("%s %w", "UplinkUEAssociatedLPPaTransport.protocolIEs:", err), "UplinkUEAssociatedLPPaTransport")
	}
	return v, aper.OperationError(nil, "UplinkUEAssociatedLPPaTransport")
}
func NewUplinkNonUEAssociatedLPPaTransport(fields s14.UplinkNonUEAssociatedLPPaTransportIEContainer, options ...aper.BuildOption) (s55.UplinkNonUEAssociatedLPPaTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s55.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s14.UplinkNonUEAssociatedLPPaTransportIEField](bb, uint64(len(fields))); err != nil {
		return s55.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	v := s55.UplinkNonUEAssociatedLPPaTransport{ProtocolIEs: make(s14.UplinkNonUEAssociatedLPPaTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUplinkNonUEAssociatedLPPaTransportBudget(&v, budget)
	if err != nil {
		return s55.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s55.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UplinkNonUEAssociatedLPPaTransport")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s55.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UplinkNonUEAssociatedLPPaTransport")
	}
	if _, err := s55.BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s55.UplinkNonUEAssociatedLPPaTransport{}, aper.OperationError(fmt.Errorf("%s %w", "UplinkNonUEAssociatedLPPaTransport.protocolIEs:", err), "UplinkNonUEAssociatedLPPaTransport")
	}
	return v, aper.OperationError(nil, "UplinkNonUEAssociatedLPPaTransport")
}
func NewUERadioCapabilityMatchRequest(fields s14.UERadioCapabilityMatchRequestIEContainer, options ...aper.BuildOption) (s46.UERadioCapabilityMatchRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.UERadioCapabilityMatchRequest{}, aper.OperationError(err, "UERadioCapabilityMatchRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s14.UERadioCapabilityMatchRequestIEField](bb, uint64(len(fields))); err != nil {
		return s46.UERadioCapabilityMatchRequest{}, aper.OperationError(err, "UERadioCapabilityMatchRequest")
	}
	v := s46.UERadioCapabilityMatchRequest{ProtocolIEs: make(s14.UERadioCapabilityMatchRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUERadioCapabilityMatchRequestBudget(&v, budget)
	if err != nil {
		return s46.UERadioCapabilityMatchRequest{}, aper.OperationError(err, "UERadioCapabilityMatchRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s46.UERadioCapabilityMatchRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UERadioCapabilityMatchRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.UERadioCapabilityMatchRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UERadioCapabilityMatchRequest")
	}
	if _, err := s46.BridgeUERadioCapabilityMatchRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.UERadioCapabilityMatchRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UERadioCapabilityMatchRequest.protocolIEs:", err), "UERadioCapabilityMatchRequest")
	}
	return v, aper.OperationError(nil, "UERadioCapabilityMatchRequest")
}
func NewUERadioCapabilityMatchResponse(fields s28.UERadioCapabilityMatchResponseIEContainer, options ...aper.BuildOption) (s46.UERadioCapabilityMatchResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.UERadioCapabilityMatchResponse{}, aper.OperationError(err, "UERadioCapabilityMatchResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s28.UERadioCapabilityMatchResponseIEField](bb, uint64(len(fields))); err != nil {
		return s46.UERadioCapabilityMatchResponse{}, aper.OperationError(err, "UERadioCapabilityMatchResponse")
	}
	v := s46.UERadioCapabilityMatchResponse{ProtocolIEs: make(s28.UERadioCapabilityMatchResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUERadioCapabilityMatchResponseBudget(&v, budget)
	if err != nil {
		return s46.UERadioCapabilityMatchResponse{}, aper.OperationError(err, "UERadioCapabilityMatchResponse")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s46.UERadioCapabilityMatchResponse{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UERadioCapabilityMatchResponse")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.UERadioCapabilityMatchResponse{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UERadioCapabilityMatchResponse")
	}
	if _, err := s46.BridgeUERadioCapabilityMatchResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.UERadioCapabilityMatchResponse{}, aper.OperationError(fmt.Errorf("%s %w", "UERadioCapabilityMatchResponse.protocolIEs:", err), "UERadioCapabilityMatchResponse")
	}
	return v, aper.OperationError(nil, "UERadioCapabilityMatchResponse")
}
func NewPWSRestartIndication(fields s55.PWSRestartIndicationIEContainer, options ...aper.BuildOption) (s55.PWSRestartIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s55.PWSRestartIndication{}, aper.OperationError(err, "PWSRestartIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s55.PWSRestartIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s55.PWSRestartIndication{}, aper.OperationError(err, "PWSRestartIndication")
	}
	v := s55.PWSRestartIndication{ProtocolIEs: make(s55.PWSRestartIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidatePWSRestartIndicationBudget(&v, budget)
	if err != nil {
		return s55.PWSRestartIndication{}, aper.OperationError(err, "PWSRestartIndication")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s55.PWSRestartIndication{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "PWSRestartIndication")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s55.PWSRestartIndication{}, aper.OperationError(&s25.BuildError{Issues: issues}, "PWSRestartIndication")
	}
	if _, err := s55.BridgePWSRestartIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s55.PWSRestartIndication{}, aper.OperationError(fmt.Errorf("%s %w", "PWSRestartIndication.protocolIEs:", err), "PWSRestartIndication")
	}
	return v, aper.OperationError(nil, "PWSRestartIndication")
}
func NewERABModificationIndication(fields s56.ERABModificationIndicationIEContainer, options ...aper.BuildOption) (s57.ERABModificationIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s57.ERABModificationIndication{}, aper.OperationError(err, "ERABModificationIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s56.ERABModificationIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s57.ERABModificationIndication{}, aper.OperationError(err, "ERABModificationIndication")
	}
	v := s57.ERABModificationIndication{ProtocolIEs: make(s56.ERABModificationIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABModificationIndicationBudget(&v, budget)
	if err != nil {
		return s57.ERABModificationIndication{}, aper.OperationError(err, "ERABModificationIndication")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s57.ERABModificationIndication{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ERABModificationIndication")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s57.ERABModificationIndication{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ERABModificationIndication")
	}
	if _, err := s57.BridgeERABModificationIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s57.ERABModificationIndication{}, aper.OperationError(fmt.Errorf("%s %w", "ERABModificationIndication.protocolIEs:", err), "ERABModificationIndication")
	}
	return v, aper.OperationError(nil, "ERABModificationIndication")
}
func NewUEContextModificationIndication(fields s24.UEContextModificationIndicationIEContainer, options ...aper.BuildOption) (s46.UEContextModificationIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.UEContextModificationIndication{}, aper.OperationError(err, "UEContextModificationIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s24.UEContextModificationIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s46.UEContextModificationIndication{}, aper.OperationError(err, "UEContextModificationIndication")
	}
	v := s46.UEContextModificationIndication{ProtocolIEs: make(s24.UEContextModificationIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextModificationIndicationBudget(&v, budget)
	if err != nil {
		return s46.UEContextModificationIndication{}, aper.OperationError(err, "UEContextModificationIndication")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s46.UEContextModificationIndication{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UEContextModificationIndication")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.UEContextModificationIndication{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UEContextModificationIndication")
	}
	if _, err := s46.BridgeUEContextModificationIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.UEContextModificationIndication{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextModificationIndication.protocolIEs:", err), "UEContextModificationIndication")
	}
	return v, aper.OperationError(nil, "UEContextModificationIndication")
}
func NewUEContextModificationConfirm(fields s27.UEContextModificationConfirmIEContainer, options ...aper.BuildOption) (s45.UEContextModificationConfirm, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s45.UEContextModificationConfirm{}, aper.OperationError(err, "UEContextModificationConfirm")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s27.UEContextModificationConfirmIEField](bb, uint64(len(fields))); err != nil {
		return s45.UEContextModificationConfirm{}, aper.OperationError(err, "UEContextModificationConfirm")
	}
	v := s45.UEContextModificationConfirm{ProtocolIEs: make(s27.UEContextModificationConfirmIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextModificationConfirmBudget(&v, budget)
	if err != nil {
		return s45.UEContextModificationConfirm{}, aper.OperationError(err, "UEContextModificationConfirm")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s45.UEContextModificationConfirm{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UEContextModificationConfirm")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s45.UEContextModificationConfirm{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UEContextModificationConfirm")
	}
	if _, err := s45.BridgeUEContextModificationConfirmMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s45.UEContextModificationConfirm{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextModificationConfirm.protocolIEs:", err), "UEContextModificationConfirm")
	}
	return v, aper.OperationError(nil, "UEContextModificationConfirm")
}
func NewUEContextSuspendRequest(fields s56.UEContextSuspendRequestIEContainer, options ...aper.BuildOption) (s57.UEContextSuspendRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s57.UEContextSuspendRequest{}, aper.OperationError(err, "UEContextSuspendRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s56.UEContextSuspendRequestIEField](bb, uint64(len(fields))); err != nil {
		return s57.UEContextSuspendRequest{}, aper.OperationError(err, "UEContextSuspendRequest")
	}
	v := s57.UEContextSuspendRequest{ProtocolIEs: make(s56.UEContextSuspendRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextSuspendRequestBudget(&v, budget)
	if err != nil {
		return s57.UEContextSuspendRequest{}, aper.OperationError(err, "UEContextSuspendRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s57.UEContextSuspendRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UEContextSuspendRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s57.UEContextSuspendRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UEContextSuspendRequest")
	}
	if _, err := s57.BridgeUEContextSuspendRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s57.UEContextSuspendRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextSuspendRequest.protocolIEs:", err), "UEContextSuspendRequest")
	}
	return v, aper.OperationError(nil, "UEContextSuspendRequest")
}
func NewUEContextSuspendResponse(fields s36.UEContextSuspendResponseIEContainer, options ...aper.BuildOption) (s46.UEContextSuspendResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.UEContextSuspendResponse{}, aper.OperationError(err, "UEContextSuspendResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s36.UEContextSuspendResponseIEField](bb, uint64(len(fields))); err != nil {
		return s46.UEContextSuspendResponse{}, aper.OperationError(err, "UEContextSuspendResponse")
	}
	v := s46.UEContextSuspendResponse{ProtocolIEs: make(s36.UEContextSuspendResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextSuspendResponseBudget(&v, budget)
	if err != nil {
		return s46.UEContextSuspendResponse{}, aper.OperationError(err, "UEContextSuspendResponse")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s46.UEContextSuspendResponse{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UEContextSuspendResponse")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.UEContextSuspendResponse{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UEContextSuspendResponse")
	}
	if _, err := s46.BridgeUEContextSuspendResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.UEContextSuspendResponse{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextSuspendResponse.protocolIEs:", err), "UEContextSuspendResponse")
	}
	return v, aper.OperationError(nil, "UEContextSuspendResponse")
}
func NewUEContextResumeRequest(fields s48.UEContextResumeRequestIEContainer, options ...aper.BuildOption) (s48.UEContextResumeRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s48.UEContextResumeRequest{}, aper.OperationError(err, "UEContextResumeRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s48.UEContextResumeRequestIEField](bb, uint64(len(fields))); err != nil {
		return s48.UEContextResumeRequest{}, aper.OperationError(err, "UEContextResumeRequest")
	}
	v := s48.UEContextResumeRequest{ProtocolIEs: make(s48.UEContextResumeRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextResumeRequestBudget(&v, budget)
	if err != nil {
		return s48.UEContextResumeRequest{}, aper.OperationError(err, "UEContextResumeRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s48.UEContextResumeRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UEContextResumeRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s48.UEContextResumeRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UEContextResumeRequest")
	}
	if _, err := s48.BridgeUEContextResumeRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s48.UEContextResumeRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextResumeRequest.protocolIEs:", err), "UEContextResumeRequest")
	}
	return v, aper.OperationError(nil, "UEContextResumeRequest")
}
func NewUEContextResumeResponse(fields s48.UEContextResumeResponseIEContainer, options ...aper.BuildOption) (s49.UEContextResumeResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s49.UEContextResumeResponse{}, aper.OperationError(err, "UEContextResumeResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s48.UEContextResumeResponseIEField](bb, uint64(len(fields))); err != nil {
		return s49.UEContextResumeResponse{}, aper.OperationError(err, "UEContextResumeResponse")
	}
	v := s49.UEContextResumeResponse{ProtocolIEs: make(s48.UEContextResumeResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextResumeResponseBudget(&v, budget)
	if err != nil {
		return s49.UEContextResumeResponse{}, aper.OperationError(err, "UEContextResumeResponse")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s49.UEContextResumeResponse{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UEContextResumeResponse")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s49.UEContextResumeResponse{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UEContextResumeResponse")
	}
	if _, err := s49.BridgeUEContextResumeResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s49.UEContextResumeResponse{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextResumeResponse.protocolIEs:", err), "UEContextResumeResponse")
	}
	return v, aper.OperationError(nil, "UEContextResumeResponse")
}
func NewUEContextResumeFailure(fields s27.UEContextResumeFailureIEContainer, options ...aper.BuildOption) (s46.UEContextResumeFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.UEContextResumeFailure{}, aper.OperationError(err, "UEContextResumeFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s27.UEContextResumeFailureIEField](bb, uint64(len(fields))); err != nil {
		return s46.UEContextResumeFailure{}, aper.OperationError(err, "UEContextResumeFailure")
	}
	v := s46.UEContextResumeFailure{ProtocolIEs: make(s27.UEContextResumeFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextResumeFailureBudget(&v, budget)
	if err != nil {
		return s46.UEContextResumeFailure{}, aper.OperationError(err, "UEContextResumeFailure")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s46.UEContextResumeFailure{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UEContextResumeFailure")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.UEContextResumeFailure{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UEContextResumeFailure")
	}
	if _, err := s46.BridgeUEContextResumeFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.UEContextResumeFailure{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextResumeFailure.protocolIEs:", err), "UEContextResumeFailure")
	}
	return v, aper.OperationError(nil, "UEContextResumeFailure")
}
func NewUEInformationTransfer(fields s39.UEInformationTransferIEContainer, options ...aper.BuildOption) (s46.UEInformationTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.UEInformationTransfer{}, aper.OperationError(err, "UEInformationTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s39.UEInformationTransferIEField](bb, uint64(len(fields))); err != nil {
		return s46.UEInformationTransfer{}, aper.OperationError(err, "UEInformationTransfer")
	}
	v := s46.UEInformationTransfer{ProtocolIEs: make(s39.UEInformationTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEInformationTransferBudget(&v, budget)
	if err != nil {
		return s46.UEInformationTransfer{}, aper.OperationError(err, "UEInformationTransfer")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s46.UEInformationTransfer{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UEInformationTransfer")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.UEInformationTransfer{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UEInformationTransfer")
	}
	if _, err := s46.BridgeUEInformationTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.UEInformationTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "UEInformationTransfer.protocolIEs:", err), "UEInformationTransfer")
	}
	return v, aper.OperationError(nil, "UEInformationTransfer")
}
func NewENBCPRelocationIndication(fields s47.ENBCPRelocationIndicationIEContainer, options ...aper.BuildOption) (s47.ENBCPRelocationIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s47.ENBCPRelocationIndication{}, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s47.ENBCPRelocationIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s47.ENBCPRelocationIndication{}, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	v := s47.ENBCPRelocationIndication{ProtocolIEs: make(s47.ENBCPRelocationIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBCPRelocationIndicationBudget(&v, budget)
	if err != nil {
		return s47.ENBCPRelocationIndication{}, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s47.ENBCPRelocationIndication{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ENBCPRelocationIndication")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s47.ENBCPRelocationIndication{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ENBCPRelocationIndication")
	}
	if _, err := s47.BridgeENBCPRelocationIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s47.ENBCPRelocationIndication{}, aper.OperationError(fmt.Errorf("%s %w", "ENBCPRelocationIndication.protocolIEs:", err), "ENBCPRelocationIndication")
	}
	return v, aper.OperationError(nil, "ENBCPRelocationIndication")
}
func NewSecondaryRATDataUsageReport(fields s56.SecondaryRATDataUsageReportIEContainer, options ...aper.BuildOption) (s57.SecondaryRATDataUsageReport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s57.SecondaryRATDataUsageReport{}, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s56.SecondaryRATDataUsageReportIEField](bb, uint64(len(fields))); err != nil {
		return s57.SecondaryRATDataUsageReport{}, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	v := s57.SecondaryRATDataUsageReport{ProtocolIEs: make(s56.SecondaryRATDataUsageReportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateSecondaryRATDataUsageReportBudget(&v, budget)
	if err != nil {
		return s57.SecondaryRATDataUsageReport{}, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s57.SecondaryRATDataUsageReport{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "SecondaryRATDataUsageReport")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s57.SecondaryRATDataUsageReport{}, aper.OperationError(&s25.BuildError{Issues: issues}, "SecondaryRATDataUsageReport")
	}
	if _, err := s57.BridgeSecondaryRATDataUsageReportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s57.SecondaryRATDataUsageReport{}, aper.OperationError(fmt.Errorf("%s %w", "SecondaryRATDataUsageReport.protocolIEs:", err), "SecondaryRATDataUsageReport")
	}
	return v, aper.OperationError(nil, "SecondaryRATDataUsageReport")
}
func NewUERadioCapabilityIDMappingRequest(fields s14.UERadioCapabilityIDMappingRequestIEContainer, options ...aper.BuildOption) (s46.UERadioCapabilityIDMappingRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.UERadioCapabilityIDMappingRequest{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s14.UERadioCapabilityIDMappingRequestIEField](bb, uint64(len(fields))); err != nil {
		return s46.UERadioCapabilityIDMappingRequest{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	v := s46.UERadioCapabilityIDMappingRequest{ProtocolIEs: make(s14.UERadioCapabilityIDMappingRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUERadioCapabilityIDMappingRequestBudget(&v, budget)
	if err != nil {
		return s46.UERadioCapabilityIDMappingRequest{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s46.UERadioCapabilityIDMappingRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UERadioCapabilityIDMappingRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.UERadioCapabilityIDMappingRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UERadioCapabilityIDMappingRequest")
	}
	if _, err := s46.BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.UERadioCapabilityIDMappingRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UERadioCapabilityIDMappingRequest.protocolIEs:", err), "UERadioCapabilityIDMappingRequest")
	}
	return v, aper.OperationError(nil, "UERadioCapabilityIDMappingRequest")
}
func NewUERadioCapabilityIDMappingResponse(fields s28.UERadioCapabilityIDMappingResponseIEContainer, options ...aper.BuildOption) (s46.UERadioCapabilityIDMappingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s46.UERadioCapabilityIDMappingResponse{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s28.UERadioCapabilityIDMappingResponseIEField](bb, uint64(len(fields))); err != nil {
		return s46.UERadioCapabilityIDMappingResponse{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	v := s46.UERadioCapabilityIDMappingResponse{ProtocolIEs: make(s28.UERadioCapabilityIDMappingResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUERadioCapabilityIDMappingResponseBudget(&v, budget)
	if err != nil {
		return s46.UERadioCapabilityIDMappingResponse{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s46.UERadioCapabilityIDMappingResponse{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UERadioCapabilityIDMappingResponse")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s46.UERadioCapabilityIDMappingResponse{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UERadioCapabilityIDMappingResponse")
	}
	if _, err := s46.BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s46.UERadioCapabilityIDMappingResponse{}, aper.OperationError(fmt.Errorf("%s %w", "UERadioCapabilityIDMappingResponse.protocolIEs:", err), "UERadioCapabilityIDMappingResponse")
	}
	return v, aper.OperationError(nil, "UERadioCapabilityIDMappingResponse")
}
func BridgeValidateHandoverRequiredBudget(v *s43.HandoverRequired, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverRequired")
	}
	rows := []s00.FieldInfo{s43.HandoverRequiredIEs().MMEUES1APID().Info(), s43.HandoverRequiredIEs().ENBUES1APID().Info(), s43.HandoverRequiredIEs().HandoverType().Info(), s43.HandoverRequiredIEs().Cause().Info(), s43.HandoverRequiredIEs().TargetID().Info(), s43.HandoverRequiredIEs().DirectForwardingPathAvailability().Info(), s43.HandoverRequiredIEs().SRVCCHOIndication().Info(), s43.HandoverRequiredIEs().SourceToTargetTransparentContainer().Info(), s43.HandoverRequiredIEs().SourceToTargetTransparentContainerSecondary().Info(), s43.HandoverRequiredIEs().MSClassmark2().Info(), s43.HandoverRequiredIEs().MSClassmark3().Info(), s43.HandoverRequiredIEs().CSGId().Info(), s43.HandoverRequiredIEs().CellAccessMode().Info(), s43.HandoverRequiredIEs().PSServiceNotAvailable().Info()}
	report := s43.BridgeHandoverRequiredIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverRequired.protocolIEs", budget)
	BridgeWalkValidationHandoverRequired(v, &report, "HandoverRequired", true)
	return report, nil
}
func BridgeValidateHandoverNotifyBudget(v *s44.HandoverNotify, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverNotify")
	}
	rows := []s00.FieldInfo{s44.HandoverNotifyIEs().MMEUES1APID().Info(), s44.HandoverNotifyIEs().ENBUES1APID().Info(), s44.HandoverNotifyIEs().EUTRANCGI().Info(), s44.HandoverNotifyIEs().TAI().Info(), s44.HandoverNotifyIEs().TunnelInformationForBBF().Info(), s44.HandoverNotifyIEs().LHNID().Info(), s44.HandoverNotifyIEs().PSCellInformation().Info(), s44.HandoverNotifyIEs().NotifySourceeNB().Info(), s44.HandoverNotifyIEs().LTENTNTAIInformation().Info()}
	report := s45.BridgeHandoverNotifyIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverNotify.protocolIEs", budget)
	BridgeWalkValidationHandoverNotify(v, &report, "HandoverNotify", true)
	return report, nil
}
func BridgeValidatePathSwitchRequestBudget(v *s51.PathSwitchRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil PathSwitchRequest")
	}
	rows := []s00.FieldInfo{s51.PathSwitchRequestIEs().ENBUES1APID().Info(), s51.PathSwitchRequestIEs().ERABToBeSwitchedDLList().Info(), s51.PathSwitchRequestIEs().SourceMMEUES1APID().Info(), s51.PathSwitchRequestIEs().EUTRANCGI().Info(), s51.PathSwitchRequestIEs().TAI().Info(), s51.PathSwitchRequestIEs().UESecurityCapabilities().Info(), s51.PathSwitchRequestIEs().CSGId().Info(), s51.PathSwitchRequestIEs().CellAccessMode().Info(), s51.PathSwitchRequestIEs().SourceMMEGUMMEI().Info(), s51.PathSwitchRequestIEs().CSGMembershipStatus().Info(), s51.PathSwitchRequestIEs().TunnelInformationForBBF().Info(), s51.PathSwitchRequestIEs().LHNID().Info(), s51.PathSwitchRequestIEs().RRCResumeCause().Info(), s51.PathSwitchRequestIEs().NRUESecurityCapabilities().Info(), s51.PathSwitchRequestIEs().PSCellInformation().Info(), s51.PathSwitchRequestIEs().LTENTNTAIInformation().Info()}
	report := s51.BridgePathSwitchRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "PathSwitchRequest.protocolIEs", budget)
	BridgeWalkValidationPathSwitchRequest(v, &report, "PathSwitchRequest", true)
	return report, nil
}
func BridgeValidatePathSwitchRequestAcknowledgeBudget(v *s58.PathSwitchRequestAcknowledge, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil PathSwitchRequestAcknowledge")
	}
	rows := []s00.FieldInfo{s58.PathSwitchRequestAcknowledgeIEs().MMEUES1APID().Info(), s58.PathSwitchRequestAcknowledgeIEs().ENBUES1APID().Info(), s58.PathSwitchRequestAcknowledgeIEs().UEaggregateMaximumBitrate().Info(), s58.PathSwitchRequestAcknowledgeIEs().ERABToBeSwitchedULList().Info(), s58.PathSwitchRequestAcknowledgeIEs().ERABToBeReleasedList().Info(), s58.PathSwitchRequestAcknowledgeIEs().SecurityContext().Info(), s58.PathSwitchRequestAcknowledgeIEs().CriticalityDiagnostics().Info(), s58.PathSwitchRequestAcknowledgeIEs().MMEUES1APID2().Info(), s58.PathSwitchRequestAcknowledgeIEs().CSGMembershipStatus().Info(), s58.PathSwitchRequestAcknowledgeIEs().ProSeAuthorized().Info(), s58.PathSwitchRequestAcknowledgeIEs().UEUserPlaneCIoTSupportIndicator().Info(), s58.PathSwitchRequestAcknowledgeIEs().V2XServicesAuthorized().Info(), s58.PathSwitchRequestAcknowledgeIEs().UESidelinkAggregateMaximumBitrate().Info(), s58.PathSwitchRequestAcknowledgeIEs().EnhancedCoverageRestricted().Info(), s58.PathSwitchRequestAcknowledgeIEs().NRUESecurityCapabilities().Info(), s58.PathSwitchRequestAcknowledgeIEs().CEModeBRestricted().Info(), s58.PathSwitchRequestAcknowledgeIEs().AerialUEsubscriptionInformation().Info(), s58.PathSwitchRequestAcknowledgeIEs().PendingDataIndication().Info(), s58.PathSwitchRequestAcknowledgeIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s58.PathSwitchRequestAcknowledgeIEs().HandoverRestrictionList().Info(), s58.PathSwitchRequestAcknowledgeIEs().AdditionalRRMPriorityIndex().Info(), s58.PathSwitchRequestAcknowledgeIEs().NRV2XServicesAuthorized().Info(), s58.PathSwitchRequestAcknowledgeIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s58.PathSwitchRequestAcknowledgeIEs().PC5QoSParameters().Info(), s58.PathSwitchRequestAcknowledgeIEs().UERadioCapabilityID().Info(), s58.PathSwitchRequestAcknowledgeIEs().UESecurityCapabilities().Info(), s58.PathSwitchRequestAcknowledgeIEs().ERABToBeUpdatedList().Info(), s58.PathSwitchRequestAcknowledgeIEs().TimeRefDistribution().Info()}
	report := s58.BridgePathSwitchRequestAcknowledgeIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "PathSwitchRequestAcknowledge.protocolIEs", budget)
	BridgeWalkValidationPathSwitchRequestAcknowledge(v, &report, "PathSwitchRequestAcknowledge", true)
	return report, nil
}
func BridgeValidateERABSetupRequestBudget(v *s51.ERABSetupRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABSetupRequest")
	}
	rows := []s00.FieldInfo{s51.ERABSetupRequestIEs().MMEUES1APID().Info(), s51.ERABSetupRequestIEs().ENBUES1APID().Info(), s51.ERABSetupRequestIEs().UEaggregateMaximumBitrate().Info(), s51.ERABSetupRequestIEs().ERABToBeSetupListBearerSUReq().Info()}
	report := s51.BridgeERABSetupRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABSetupRequest.protocolIEs", budget)
	BridgeWalkValidationERABSetupRequest(v, &report, "ERABSetupRequest", true)
	return report, nil
}
func BridgeValidateERABSetupResponseBudget(v *s57.ERABSetupResponse, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABSetupResponse")
	}
	rows := []s00.FieldInfo{s57.ERABSetupResponseIEs().MMEUES1APID().Info(), s57.ERABSetupResponseIEs().ENBUES1APID().Info(), s57.ERABSetupResponseIEs().ERABSetupListBearerSURes().Info(), s57.ERABSetupResponseIEs().ERABFailedToSetupListBearerSURes().Info(), s57.ERABSetupResponseIEs().CriticalityDiagnostics().Info(), s57.ERABSetupResponseIEs().UserLocationInformation().Info()}
	report := s57.BridgeERABSetupResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABSetupResponse.protocolIEs", budget)
	BridgeWalkValidationERABSetupResponse(v, &report, "ERABSetupResponse", true)
	return report, nil
}
func BridgeValidateERABModifyRequestBudget(v *s51.ERABModifyRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABModifyRequest")
	}
	rows := []s00.FieldInfo{s51.ERABModifyRequestIEs().MMEUES1APID().Info(), s51.ERABModifyRequestIEs().ENBUES1APID().Info(), s51.ERABModifyRequestIEs().UEaggregateMaximumBitrate().Info(), s51.ERABModifyRequestIEs().ERABToBeModifiedListBearerModReq().Info(), s51.ERABModifyRequestIEs().SecondaryRATDataUsageRequest().Info()}
	report := s51.BridgeERABModifyRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABModifyRequest.protocolIEs", budget)
	BridgeWalkValidationERABModifyRequest(v, &report, "ERABModifyRequest", true)
	return report, nil
}
func BridgeValidateERABModifyResponseBudget(v *s57.ERABModifyResponse, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABModifyResponse")
	}
	rows := []s00.FieldInfo{s57.ERABModifyResponseIEs().MMEUES1APID().Info(), s57.ERABModifyResponseIEs().ENBUES1APID().Info(), s57.ERABModifyResponseIEs().ERABModifyListBearerModRes().Info(), s57.ERABModifyResponseIEs().ERABFailedToModifyList().Info(), s57.ERABModifyResponseIEs().CriticalityDiagnostics().Info(), s57.ERABModifyResponseIEs().SecondaryRATDataUsageReportList().Info(), s57.ERABModifyResponseIEs().UserLocationInformation().Info()}
	report := s57.BridgeERABModifyResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABModifyResponse.protocolIEs", budget)
	BridgeWalkValidationERABModifyResponse(v, &report, "ERABModifyResponse", true)
	return report, nil
}
func BridgeValidateERABReleaseCommandBudget(v *s49.ERABReleaseCommand, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABReleaseCommand")
	}
	rows := []s00.FieldInfo{s49.ERABReleaseCommandIEs().MMEUES1APID().Info(), s49.ERABReleaseCommandIEs().ENBUES1APID().Info(), s49.ERABReleaseCommandIEs().UEaggregateMaximumBitrate().Info(), s49.ERABReleaseCommandIEs().ERABToBeReleasedList().Info(), s49.ERABReleaseCommandIEs().NASPDU().Info()}
	report := s49.BridgeERABReleaseCommandIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABReleaseCommand.protocolIEs", budget)
	BridgeWalkValidationERABReleaseCommand(v, &report, "ERABReleaseCommand", true)
	return report, nil
}
func BridgeValidateERABReleaseResponseBudget(v *s57.ERABReleaseResponse, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABReleaseResponse")
	}
	rows := []s00.FieldInfo{s57.ERABReleaseResponseIEs().MMEUES1APID().Info(), s57.ERABReleaseResponseIEs().ENBUES1APID().Info(), s57.ERABReleaseResponseIEs().ERABReleaseListBearerRelComp().Info(), s57.ERABReleaseResponseIEs().ERABFailedToReleaseList().Info(), s57.ERABReleaseResponseIEs().CriticalityDiagnostics().Info(), s57.ERABReleaseResponseIEs().UserLocationInformation().Info(), s57.ERABReleaseResponseIEs().SecondaryRATDataUsageReportList().Info()}
	report := s57.BridgeERABReleaseResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABReleaseResponse.protocolIEs", budget)
	BridgeWalkValidationERABReleaseResponse(v, &report, "ERABReleaseResponse", true)
	return report, nil
}
func BridgeValidateERABReleaseIndicationBudget(v *s57.ERABReleaseIndication, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABReleaseIndication")
	}
	rows := []s00.FieldInfo{s57.ERABReleaseIndicationIEs().MMEUES1APID().Info(), s57.ERABReleaseIndicationIEs().ENBUES1APID().Info(), s57.ERABReleaseIndicationIEs().ERABReleasedList().Info(), s57.ERABReleaseIndicationIEs().UserLocationInformation().Info(), s57.ERABReleaseIndicationIEs().SecondaryRATDataUsageReportList().Info()}
	report := s57.BridgeERABReleaseIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABReleaseIndication.protocolIEs", budget)
	BridgeWalkValidationERABReleaseIndication(v, &report, "ERABReleaseIndication", true)
	return report, nil
}
func BridgeValidateInitialUEMessageBudget(v *s45.InitialUEMessage, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil InitialUEMessage")
	}
	rows := []s00.FieldInfo{s44.InitialUEMessageIEs().ENBUES1APID().Info(), s44.InitialUEMessageIEs().NASPDU().Info(), s44.InitialUEMessageIEs().TAI().Info(), s44.InitialUEMessageIEs().EUTRANCGI().Info(), s44.InitialUEMessageIEs().RRCEstablishmentCause().Info(), s44.InitialUEMessageIEs().STMSI().Info(), s44.InitialUEMessageIEs().CSGId().Info(), s44.InitialUEMessageIEs().GUMMEIID().Info(), s44.InitialUEMessageIEs().CellAccessMode().Info(), s44.InitialUEMessageIEs().GWTransportLayerAddress().Info(), s44.InitialUEMessageIEs().RelayNodeIndicator().Info(), s44.InitialUEMessageIEs().GUMMEIType().Info(), s44.InitialUEMessageIEs().TunnelInformationForBBF().Info(), s44.InitialUEMessageIEs().SIPTOLGWTransportLayerAddress().Info(), s44.InitialUEMessageIEs().LHNID().Info(), s44.InitialUEMessageIEs().MMEGroupID().Info(), s44.InitialUEMessageIEs().UEUsageType().Info(), s44.InitialUEMessageIEs().CEModeBSupportIndicator().Info(), s44.InitialUEMessageIEs().DCNID().Info(), s44.InitialUEMessageIEs().CoverageLevel().Info(), s44.InitialUEMessageIEs().UEApplicationLayerMeasurementCapability().Info(), s44.InitialUEMessageIEs().EDTSession().Info(), s44.InitialUEMessageIEs().IABNodeIndication().Info(), s44.InitialUEMessageIEs().LTENTNTAIInformation().Info(), s44.InitialUEMessageIEs().CoarseUELocationRequested().Info()}
	report := s45.BridgeInitialUEMessageIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "InitialUEMessage.protocolIEs", budget)
	BridgeWalkValidationInitialUEMessage(v, &report, "InitialUEMessage", true)
	return report, nil
}
func BridgeValidateUplinkNASTransportBudget(v *s55.UplinkNASTransport, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UplinkNASTransport")
	}
	rows := []s00.FieldInfo{s41.UplinkNASTransportIEs().MMEUES1APID().Info(), s41.UplinkNASTransportIEs().ENBUES1APID().Info(), s41.UplinkNASTransportIEs().NASPDU().Info(), s41.UplinkNASTransportIEs().EUTRANCGI().Info(), s41.UplinkNASTransportIEs().TAI().Info(), s41.UplinkNASTransportIEs().GWTransportLayerAddress().Info(), s41.UplinkNASTransportIEs().SIPTOLGWTransportLayerAddress().Info(), s41.UplinkNASTransportIEs().LHNID().Info(), s41.UplinkNASTransportIEs().PSCellInformation().Info(), s41.UplinkNASTransportIEs().LTENTNTAIInformation().Info()}
	report := s55.BridgeUplinkNASTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UplinkNASTransport.protocolIEs", budget)
	BridgeWalkValidationUplinkNASTransport(v, &report, "UplinkNASTransport", true)
	return report, nil
}
func BridgeValidateResetBudget(v *s45.Reset, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil Reset")
	}
	rows := []s00.FieldInfo{s45.ResetIEs().Cause().Info(), s45.ResetIEs().ResetType().Info()}
	report := s45.BridgeResetIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "Reset.protocolIEs", budget)
	BridgeWalkValidationReset(v, &report, "Reset", true)
	return report, nil
}
func BridgeValidateResetAcknowledgeBudget(v *s55.ResetAcknowledge, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ResetAcknowledge")
	}
	rows := []s00.FieldInfo{s55.ResetAcknowledgeIEs().UEAssociatedLogicalS1ConnectionListResAck().Info(), s55.ResetAcknowledgeIEs().CriticalityDiagnostics().Info()}
	report := s55.BridgeResetAcknowledgeIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ResetAcknowledge.protocolIEs", budget)
	BridgeWalkValidationResetAcknowledge(v, &report, "ResetAcknowledge", true)
	return report, nil
}
func BridgeValidateUEContextReleaseRequestBudget(v *s53.UEContextReleaseRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextReleaseRequest")
	}
	rows := []s00.FieldInfo{s53.UEContextReleaseRequestIEs().MMEUES1APID().Info(), s53.UEContextReleaseRequestIEs().ENBUES1APID().Info(), s53.UEContextReleaseRequestIEs().Cause().Info(), s53.UEContextReleaseRequestIEs().GWContextReleaseIndication().Info(), s53.UEContextReleaseRequestIEs().SecondaryRATDataUsageReportList().Info()}
	report := s53.BridgeUEContextReleaseRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextReleaseRequest.protocolIEs", budget)
	BridgeWalkValidationUEContextReleaseRequest(v, &report, "UEContextReleaseRequest", true)
	return report, nil
}
func BridgeValidateUplinkS1cdma2000tunnellingBudget(v *s55.UplinkS1cdma2000tunnelling, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UplinkS1cdma2000tunnelling")
	}
	rows := []s00.FieldInfo{s25.UplinkS1cdma2000tunnellingIEs().MMEUES1APID().Info(), s25.UplinkS1cdma2000tunnellingIEs().ENBUES1APID().Info(), s25.UplinkS1cdma2000tunnellingIEs().Cdma2000RATType().Info(), s25.UplinkS1cdma2000tunnellingIEs().Cdma2000SectorID().Info(), s25.UplinkS1cdma2000tunnellingIEs().Cdma2000HORequiredIndication().Info(), s25.UplinkS1cdma2000tunnellingIEs().Cdma2000OneXSRVCCInfo().Info(), s25.UplinkS1cdma2000tunnellingIEs().Cdma2000OneXRAND().Info(), s25.UplinkS1cdma2000tunnellingIEs().Cdma2000PDU().Info(), s25.UplinkS1cdma2000tunnellingIEs().EUTRANRoundTripDelayEstimationInfo().Info()}
	report := s55.BridgeUplinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UplinkS1cdma2000tunnelling.protocolIEs", budget)
	BridgeWalkValidationUplinkS1cdma2000tunnelling(v, &report, "UplinkS1cdma2000tunnelling", true)
	return report, nil
}
func BridgeValidateUEContextModificationResponseBudget(v *s46.UEContextModificationResponse, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextModificationResponse")
	}
	rows := []s00.FieldInfo{s27.UEContextModificationResponseIEs().MMEUES1APID().Info(), s27.UEContextModificationResponseIEs().ENBUES1APID().Info(), s27.UEContextModificationResponseIEs().CriticalityDiagnostics().Info()}
	report := s46.BridgeUEContextModificationResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextModificationResponse.protocolIEs", budget)
	BridgeWalkValidationUEContextModificationResponse(v, &report, "UEContextModificationResponse", true)
	return report, nil
}
func BridgeValidateUEContextModificationFailureBudget(v *s45.UEContextModificationFailure, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextModificationFailure")
	}
	rows := []s00.FieldInfo{s27.UEContextModificationFailureIEs().MMEUES1APID().Info(), s27.UEContextModificationFailureIEs().ENBUES1APID().Info(), s27.UEContextModificationFailureIEs().Cause().Info(), s27.UEContextModificationFailureIEs().CriticalityDiagnostics().Info()}
	report := s46.BridgeUEContextModificationFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextModificationFailure.protocolIEs", budget)
	BridgeWalkValidationUEContextModificationFailure(v, &report, "UEContextModificationFailure", true)
	return report, nil
}
func BridgeValidateUECapabilityInfoIndicationBudget(v *s45.UECapabilityInfoIndication, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UECapabilityInfoIndication")
	}
	rows := []s00.FieldInfo{s14.UECapabilityInfoIndicationIEs().MMEUES1APID().Info(), s14.UECapabilityInfoIndicationIEs().ENBUES1APID().Info(), s14.UECapabilityInfoIndicationIEs().UERadioCapability().Info(), s14.UECapabilityInfoIndicationIEs().UERadioCapabilityForPaging().Info(), s14.UECapabilityInfoIndicationIEs().UEApplicationLayerMeasurementCapability().Info(), s14.UECapabilityInfoIndicationIEs().LTEMIndication().Info(), s14.UECapabilityInfoIndicationIEs().UERadioCapabilityNRFormat().Info(), s14.UECapabilityInfoIndicationIEs().UERadioCapabilityForPagingNRFormat().Info()}
	report := s45.BridgeUECapabilityInfoIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UECapabilityInfoIndication.protocolIEs", budget)
	BridgeWalkValidationUECapabilityInfoIndication(v, &report, "UECapabilityInfoIndication", true)
	return report, nil
}
func BridgeValidateUEContextReleaseCommandBudget(v *s47.UEContextReleaseCommand, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextReleaseCommand")
	}
	rows := []s00.FieldInfo{s46.UEContextReleaseCommandIEs().UES1APIDs().Info(), s46.UEContextReleaseCommandIEs().Cause().Info()}
	report := s47.BridgeUEContextReleaseCommandIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextReleaseCommand.protocolIEs", budget)
	BridgeWalkValidationUEContextReleaseCommand(v, &report, "UEContextReleaseCommand", true)
	return report, nil
}
func BridgeValidateUEContextReleaseCompleteBudget(v *s57.UEContextReleaseComplete, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextReleaseComplete")
	}
	rows := []s00.FieldInfo{s57.UEContextReleaseCompleteIEs().MMEUES1APID().Info(), s57.UEContextReleaseCompleteIEs().ENBUES1APID().Info(), s57.UEContextReleaseCompleteIEs().CriticalityDiagnostics().Info(), s57.UEContextReleaseCompleteIEs().UserLocationInformation().Info(), s57.UEContextReleaseCompleteIEs().InformationOnRecommendedCellsAndENBsForPaging().Info(), s57.UEContextReleaseCompleteIEs().CellIdentifierAndCELevelForCECapableUEs().Info(), s57.UEContextReleaseCompleteIEs().SecondaryRATDataUsageReportList().Info(), s57.UEContextReleaseCompleteIEs().TimeSinceSecondaryNodeRelease().Info()}
	report := s57.BridgeUEContextReleaseCompleteIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextReleaseComplete.protocolIEs", budget)
	BridgeWalkValidationUEContextReleaseComplete(v, &report, "UEContextReleaseComplete", true)
	return report, nil
}
func BridgeValidateTraceFailureIndicationBudget(v *s44.TraceFailureIndication, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil TraceFailureIndication")
	}
	rows := []s00.FieldInfo{s24.TraceFailureIndicationIEs().MMEUES1APID().Info(), s24.TraceFailureIndicationIEs().ENBUES1APID().Info(), s24.TraceFailureIndicationIEs().EUTRANTraceID().Info(), s24.TraceFailureIndicationIEs().Cause().Info()}
	report := s44.BridgeTraceFailureIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "TraceFailureIndication.protocolIEs", budget)
	BridgeWalkValidationTraceFailureIndication(v, &report, "TraceFailureIndication", true)
	return report, nil
}
func BridgeValidateENBDirectInformationTransferBudget(v *s43.ENBDirectInformationTransfer, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBDirectInformationTransfer")
	}
	rows := []s00.FieldInfo{s43.ENBDirectInformationTransferIEs().InterSystemInformationTransferTypeEDT().Info()}
	report := s43.BridgeENBDirectInformationTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBDirectInformationTransfer.protocolIEs", budget)
	BridgeWalkValidationENBDirectInformationTransfer(v, &report, "ENBDirectInformationTransfer", true)
	return report, nil
}
func BridgeValidateMMEDirectInformationTransferBudget(v *s43.MMEDirectInformationTransfer, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEDirectInformationTransfer")
	}
	rows := []s00.FieldInfo{s43.MMEDirectInformationTransferIEs().InterSystemInformationTransferTypeMDT().Info()}
	report := s43.BridgeMMEDirectInformationTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEDirectInformationTransfer.protocolIEs", budget)
	BridgeWalkValidationMMEDirectInformationTransfer(v, &report, "MMEDirectInformationTransfer", true)
	return report, nil
}
func BridgeValidateKillResponseBudget(v *s42.KillResponse, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil KillResponse")
	}
	rows := []s00.FieldInfo{s41.KillResponseIEs().MessageIdentifier().Info(), s41.KillResponseIEs().SerialNumber().Info(), s41.KillResponseIEs().BroadcastCancelledAreaList().Info(), s41.KillResponseIEs().CriticalityDiagnostics().Info()}
	report := s42.BridgeKillResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "KillResponse.protocolIEs", budget)
	BridgeWalkValidationKillResponse(v, &report, "KillResponse", true)
	return report, nil
}
func BridgeValidateUplinkUEAssociatedLPPaTransportBudget(v *s55.UplinkUEAssociatedLPPaTransport, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UplinkUEAssociatedLPPaTransport")
	}
	rows := []s00.FieldInfo{s14.UplinkUEAssociatedLPPaTransportIEs().MMEUES1APID().Info(), s14.UplinkUEAssociatedLPPaTransportIEs().ENBUES1APID().Info(), s14.UplinkUEAssociatedLPPaTransportIEs().RoutingID().Info(), s14.UplinkUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
	report := s55.BridgeUplinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UplinkUEAssociatedLPPaTransport.protocolIEs", budget)
	BridgeWalkValidationUplinkUEAssociatedLPPaTransport(v, &report, "UplinkUEAssociatedLPPaTransport", true)
	return report, nil
}
func BridgeValidateUplinkNonUEAssociatedLPPaTransportBudget(v *s55.UplinkNonUEAssociatedLPPaTransport, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UplinkNonUEAssociatedLPPaTransport")
	}
	rows := []s00.FieldInfo{s14.UplinkNonUEAssociatedLPPaTransportIEs().RoutingID().Info(), s14.UplinkNonUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
	report := s55.BridgeUplinkNonUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UplinkNonUEAssociatedLPPaTransport.protocolIEs", budget)
	BridgeWalkValidationUplinkNonUEAssociatedLPPaTransport(v, &report, "UplinkNonUEAssociatedLPPaTransport", true)
	return report, nil
}
func BridgeValidateUERadioCapabilityMatchRequestBudget(v *s46.UERadioCapabilityMatchRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UERadioCapabilityMatchRequest")
	}
	rows := []s00.FieldInfo{s14.UERadioCapabilityMatchRequestIEs().MMEUES1APID().Info(), s14.UERadioCapabilityMatchRequestIEs().ENBUES1APID().Info(), s14.UERadioCapabilityMatchRequestIEs().UERadioCapability().Info(), s14.UERadioCapabilityMatchRequestIEs().UERadioCapabilityID().Info()}
	report := s46.BridgeUERadioCapabilityMatchRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UERadioCapabilityMatchRequest.protocolIEs", budget)
	BridgeWalkValidationUERadioCapabilityMatchRequest(v, &report, "UERadioCapabilityMatchRequest", true)
	return report, nil
}
func BridgeValidateUERadioCapabilityMatchResponseBudget(v *s46.UERadioCapabilityMatchResponse, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UERadioCapabilityMatchResponse")
	}
	rows := []s00.FieldInfo{s28.UERadioCapabilityMatchResponseIEs().MMEUES1APID().Info(), s28.UERadioCapabilityMatchResponseIEs().ENBUES1APID().Info(), s28.UERadioCapabilityMatchResponseIEs().VoiceSupportMatchIndicator().Info(), s28.UERadioCapabilityMatchResponseIEs().CriticalityDiagnostics().Info()}
	report := s46.BridgeUERadioCapabilityMatchResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UERadioCapabilityMatchResponse.protocolIEs", budget)
	BridgeWalkValidationUERadioCapabilityMatchResponse(v, &report, "UERadioCapabilityMatchResponse", true)
	return report, nil
}
func BridgeValidatePWSRestartIndicationBudget(v *s55.PWSRestartIndication, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil PWSRestartIndication")
	}
	rows := []s00.FieldInfo{s55.PWSRestartIndicationIEs().ECGIListForRestart().Info(), s55.PWSRestartIndicationIEs().GlobalENBID().Info(), s55.PWSRestartIndicationIEs().TAIListForRestart().Info(), s55.PWSRestartIndicationIEs().EmergencyAreaIDListForRestart().Info()}
	report := s55.BridgePWSRestartIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "PWSRestartIndication.protocolIEs", budget)
	BridgeWalkValidationPWSRestartIndication(v, &report, "PWSRestartIndication", true)
	return report, nil
}
func BridgeValidateERABModificationIndicationBudget(v *s57.ERABModificationIndication, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABModificationIndication")
	}
	rows := []s00.FieldInfo{s57.ERABModificationIndicationIEs().MMEUES1APID().Info(), s57.ERABModificationIndicationIEs().ENBUES1APID().Info(), s57.ERABModificationIndicationIEs().ERABToBeModifiedListBearerModInd().Info(), s57.ERABModificationIndicationIEs().ERABNotToBeModifiedListBearerModInd().Info(), s57.ERABModificationIndicationIEs().CSGMembershipInfo().Info(), s57.ERABModificationIndicationIEs().TunnelInformationForBBF().Info(), s57.ERABModificationIndicationIEs().SecondaryRATDataUsageReportList().Info(), s57.ERABModificationIndicationIEs().UserLocationInformation().Info()}
	report := s57.BridgeERABModificationIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABModificationIndication.protocolIEs", budget)
	BridgeWalkValidationERABModificationIndication(v, &report, "ERABModificationIndication", true)
	return report, nil
}
func BridgeValidateUEContextModificationIndicationBudget(v *s46.UEContextModificationIndication, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextModificationIndication")
	}
	rows := []s00.FieldInfo{s24.UEContextModificationIndicationIEs().MMEUES1APID().Info(), s24.UEContextModificationIndicationIEs().ENBUES1APID().Info(), s24.UEContextModificationIndicationIEs().CSGMembershipInfo().Info()}
	report := s46.BridgeUEContextModificationIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextModificationIndication.protocolIEs", budget)
	BridgeWalkValidationUEContextModificationIndication(v, &report, "UEContextModificationIndication", true)
	return report, nil
}
func BridgeValidateUEContextModificationConfirmBudget(v *s45.UEContextModificationConfirm, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextModificationConfirm")
	}
	rows := []s00.FieldInfo{s27.UEContextModificationConfirmIEs().MMEUES1APID().Info(), s27.UEContextModificationConfirmIEs().ENBUES1APID().Info(), s27.UEContextModificationConfirmIEs().CSGMembershipStatus().Info(), s27.UEContextModificationConfirmIEs().CriticalityDiagnostics().Info()}
	report := s45.BridgeUEContextModificationConfirmIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextModificationConfirm.protocolIEs", budget)
	BridgeWalkValidationUEContextModificationConfirm(v, &report, "UEContextModificationConfirm", true)
	return report, nil
}
func BridgeValidateUEContextSuspendRequestBudget(v *s57.UEContextSuspendRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextSuspendRequest")
	}
	rows := []s00.FieldInfo{s57.UEContextSuspendRequestIEs().MMEUES1APID().Info(), s57.UEContextSuspendRequestIEs().ENBUES1APID().Info(), s57.UEContextSuspendRequestIEs().InformationOnRecommendedCellsAndENBsForPaging().Info(), s57.UEContextSuspendRequestIEs().CellIdentifierAndCELevelForCECapableUEs().Info(), s57.UEContextSuspendRequestIEs().SecondaryRATDataUsageReportList().Info(), s57.UEContextSuspendRequestIEs().UserLocationInformation().Info(), s57.UEContextSuspendRequestIEs().TimeSinceSecondaryNodeRelease().Info()}
	report := s57.BridgeUEContextSuspendRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextSuspendRequest.protocolIEs", budget)
	BridgeWalkValidationUEContextSuspendRequest(v, &report, "UEContextSuspendRequest", true)
	return report, nil
}
func BridgeValidateUEContextSuspendResponseBudget(v *s46.UEContextSuspendResponse, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextSuspendResponse")
	}
	rows := []s00.FieldInfo{s37.UEContextSuspendResponseIEs().MMEUES1APID().Info(), s37.UEContextSuspendResponseIEs().ENBUES1APID().Info(), s37.UEContextSuspendResponseIEs().CriticalityDiagnostics().Info(), s37.UEContextSuspendResponseIEs().SecurityContext().Info()}
	report := s46.BridgeUEContextSuspendResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextSuspendResponse.protocolIEs", budget)
	BridgeWalkValidationUEContextSuspendResponse(v, &report, "UEContextSuspendResponse", true)
	return report, nil
}
func BridgeValidateUEContextResumeRequestBudget(v *s48.UEContextResumeRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextResumeRequest")
	}
	rows := []s00.FieldInfo{s48.UEContextResumeRequestIEs().MMEUES1APID().Info(), s48.UEContextResumeRequestIEs().ENBUES1APID().Info(), s48.UEContextResumeRequestIEs().ERABFailedToResumeListResumeReq().Info(), s48.UEContextResumeRequestIEs().RRCResumeCause().Info()}
	report := s48.BridgeUEContextResumeRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextResumeRequest.protocolIEs", budget)
	BridgeWalkValidationUEContextResumeRequest(v, &report, "UEContextResumeRequest", true)
	return report, nil
}
func BridgeValidateUEContextResumeResponseBudget(v *s49.UEContextResumeResponse, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextResumeResponse")
	}
	rows := []s00.FieldInfo{s49.UEContextResumeResponseIEs().MMEUES1APID().Info(), s49.UEContextResumeResponseIEs().ENBUES1APID().Info(), s49.UEContextResumeResponseIEs().ERABFailedToResumeListResumeRes().Info(), s49.UEContextResumeResponseIEs().CriticalityDiagnostics().Info(), s49.UEContextResumeResponseIEs().SecurityContext().Info(), s49.UEContextResumeResponseIEs().PendingDataIndication().Info()}
	report := s49.BridgeUEContextResumeResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextResumeResponse.protocolIEs", budget)
	BridgeWalkValidationUEContextResumeResponse(v, &report, "UEContextResumeResponse", true)
	return report, nil
}
func BridgeValidateUEContextResumeFailureBudget(v *s46.UEContextResumeFailure, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextResumeFailure")
	}
	rows := []s00.FieldInfo{s28.UEContextResumeFailureIEs().MMEUES1APID().Info(), s28.UEContextResumeFailureIEs().ENBUES1APID().Info(), s28.UEContextResumeFailureIEs().Cause().Info(), s28.UEContextResumeFailureIEs().CriticalityDiagnostics().Info()}
	report := s46.BridgeUEContextResumeFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextResumeFailure.protocolIEs", budget)
	BridgeWalkValidationUEContextResumeFailure(v, &report, "UEContextResumeFailure", true)
	return report, nil
}
func BridgeValidateUEInformationTransferBudget(v *s46.UEInformationTransfer, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEInformationTransfer")
	}
	rows := []s00.FieldInfo{s40.UEInformationTransferIEs().STMSI().Info(), s40.UEInformationTransferIEs().UELevelQoSParameters().Info(), s40.UEInformationTransferIEs().UERadioCapability().Info(), s40.UEInformationTransferIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s40.UEInformationTransferIEs().PendingDataIndication().Info(), s40.UEInformationTransferIEs().MaskedIMEISV().Info()}
	report := s46.BridgeUEInformationTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEInformationTransfer.protocolIEs", budget)
	BridgeWalkValidationUEInformationTransfer(v, &report, "UEInformationTransfer", true)
	return report, nil
}
func BridgeValidateENBCPRelocationIndicationBudget(v *s47.ENBCPRelocationIndication, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBCPRelocationIndication")
	}
	rows := []s00.FieldInfo{s47.ENBCPRelocationIndicationIEs().ENBUES1APID().Info(), s47.ENBCPRelocationIndicationIEs().STMSI().Info(), s47.ENBCPRelocationIndicationIEs().EUTRANCGI().Info(), s47.ENBCPRelocationIndicationIEs().TAI().Info(), s47.ENBCPRelocationIndicationIEs().ULCPSecurityInformation().Info(), s47.ENBCPRelocationIndicationIEs().LTENTNTAIInformation().Info()}
	report := s47.BridgeENBCPRelocationIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBCPRelocationIndication.protocolIEs", budget)
	BridgeWalkValidationENBCPRelocationIndication(v, &report, "ENBCPRelocationIndication", true)
	return report, nil
}
func BridgeValidateSecondaryRATDataUsageReportBudget(v *s57.SecondaryRATDataUsageReport, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil SecondaryRATDataUsageReport")
	}
	rows := []s00.FieldInfo{s57.SecondaryRATDataUsageReportIEs().MMEUES1APID().Info(), s57.SecondaryRATDataUsageReportIEs().ENBUES1APID().Info(), s57.SecondaryRATDataUsageReportIEs().SecondaryRATDataUsageReportList().Info(), s57.SecondaryRATDataUsageReportIEs().HandoverFlag().Info(), s57.SecondaryRATDataUsageReportIEs().UserLocationInformation().Info(), s57.SecondaryRATDataUsageReportIEs().TimeSinceSecondaryNodeRelease().Info()}
	report := s57.BridgeSecondaryRATDataUsageReportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "SecondaryRATDataUsageReport.protocolIEs", budget)
	BridgeWalkValidationSecondaryRATDataUsageReport(v, &report, "SecondaryRATDataUsageReport", true)
	return report, nil
}
func BridgeValidateUERadioCapabilityIDMappingRequestBudget(v *s46.UERadioCapabilityIDMappingRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UERadioCapabilityIDMappingRequest")
	}
	rows := []s00.FieldInfo{s14.UERadioCapabilityIDMappingRequestIEs().UERadioCapabilityID().Info()}
	report := s46.BridgeUERadioCapabilityIDMappingRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UERadioCapabilityIDMappingRequest.protocolIEs", budget)
	BridgeWalkValidationUERadioCapabilityIDMappingRequest(v, &report, "UERadioCapabilityIDMappingRequest", true)
	return report, nil
}
func BridgeValidateUERadioCapabilityIDMappingResponseBudget(v *s46.UERadioCapabilityIDMappingResponse, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UERadioCapabilityIDMappingResponse")
	}
	rows := []s00.FieldInfo{s28.UERadioCapabilityIDMappingResponseIEs().UERadioCapabilityID().Info(), s28.UERadioCapabilityIDMappingResponseIEs().UERadioCapability().Info(), s28.UERadioCapabilityIDMappingResponseIEs().CriticalityDiagnostics().Info()}
	report := s46.BridgeUERadioCapabilityIDMappingResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UERadioCapabilityIDMappingResponse.protocolIEs", budget)
	BridgeWalkValidationUERadioCapabilityIDMappingResponse(v, &report, "UERadioCapabilityIDMappingResponse", true)
	return report, nil
}
func ValidateHandoverRequired(v *s43.HandoverRequired, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "HandoverRequired")
	}
	report, err := BridgeValidateHandoverRequiredBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s43.BridgeHandoverRequiredMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverRequired")
}
func ValidateHandoverNotify(v *s44.HandoverNotify, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "HandoverNotify")
	}
	report, err := BridgeValidateHandoverNotifyBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s44.BridgeHandoverNotifyMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverNotify")
}
func ValidatePathSwitchRequest(v *s51.PathSwitchRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "PathSwitchRequest")
	}
	report, err := BridgeValidatePathSwitchRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s51.BridgePathSwitchRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PathSwitchRequest")
}
func ValidatePathSwitchRequestAcknowledge(v *s58.PathSwitchRequestAcknowledge, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "PathSwitchRequestAcknowledge")
	}
	report, err := BridgeValidatePathSwitchRequestAcknowledgeBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s58.BridgePathSwitchRequestAcknowledgeMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PathSwitchRequestAcknowledge")
}
func ValidateERABSetupRequest(v *s51.ERABSetupRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ERABSetupRequest")
	}
	report, err := BridgeValidateERABSetupRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s51.BridgeERABSetupRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABSetupRequest")
}
func ValidateERABSetupResponse(v *s57.ERABSetupResponse, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ERABSetupResponse")
	}
	report, err := BridgeValidateERABSetupResponseBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s57.BridgeERABSetupResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABSetupResponse")
}
func ValidateERABModifyRequest(v *s51.ERABModifyRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ERABModifyRequest")
	}
	report, err := BridgeValidateERABModifyRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s51.BridgeERABModifyRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABModifyRequest")
}
func ValidateERABModifyResponse(v *s57.ERABModifyResponse, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ERABModifyResponse")
	}
	report, err := BridgeValidateERABModifyResponseBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s57.BridgeERABModifyResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABModifyResponse")
}
func ValidateERABReleaseCommand(v *s49.ERABReleaseCommand, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ERABReleaseCommand")
	}
	report, err := BridgeValidateERABReleaseCommandBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s49.BridgeERABReleaseCommandMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABReleaseCommand")
}
func ValidateERABReleaseResponse(v *s57.ERABReleaseResponse, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ERABReleaseResponse")
	}
	report, err := BridgeValidateERABReleaseResponseBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s57.BridgeERABReleaseResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABReleaseResponse")
}
func ValidateERABReleaseIndication(v *s57.ERABReleaseIndication, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ERABReleaseIndication")
	}
	report, err := BridgeValidateERABReleaseIndicationBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s57.BridgeERABReleaseIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABReleaseIndication")
}
func ValidateInitialUEMessage(v *s45.InitialUEMessage, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "InitialUEMessage")
	}
	report, err := BridgeValidateInitialUEMessageBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s45.BridgeInitialUEMessageMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "InitialUEMessage")
}
func ValidateUplinkNASTransport(v *s55.UplinkNASTransport, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UplinkNASTransport")
	}
	report, err := BridgeValidateUplinkNASTransportBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s55.BridgeUplinkNASTransportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UplinkNASTransport")
}
func ValidateReset(v *s45.Reset, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "Reset")
	}
	report, err := BridgeValidateResetBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s45.BridgeResetMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "Reset")
}
func ValidateResetAcknowledge(v *s55.ResetAcknowledge, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ResetAcknowledge")
	}
	report, err := BridgeValidateResetAcknowledgeBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s55.BridgeResetAcknowledgeMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ResetAcknowledge")
}
func ValidateUEContextReleaseRequest(v *s53.UEContextReleaseRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UEContextReleaseRequest")
	}
	report, err := BridgeValidateUEContextReleaseRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s53.BridgeUEContextReleaseRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextReleaseRequest")
}
func ValidateUplinkS1cdma2000tunnelling(v *s55.UplinkS1cdma2000tunnelling, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
	}
	report, err := BridgeValidateUplinkS1cdma2000tunnellingBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s55.BridgeUplinkS1cdma2000tunnellingMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UplinkS1cdma2000tunnelling")
}
func ValidateUEContextModificationResponse(v *s46.UEContextModificationResponse, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UEContextModificationResponse")
	}
	report, err := BridgeValidateUEContextModificationResponseBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeUEContextModificationResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextModificationResponse")
}
func ValidateUEContextModificationFailure(v *s45.UEContextModificationFailure, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UEContextModificationFailure")
	}
	report, err := BridgeValidateUEContextModificationFailureBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s45.BridgeUEContextModificationFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextModificationFailure")
}
func ValidateUECapabilityInfoIndication(v *s45.UECapabilityInfoIndication, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UECapabilityInfoIndication")
	}
	report, err := BridgeValidateUECapabilityInfoIndicationBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s45.BridgeUECapabilityInfoIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UECapabilityInfoIndication")
}
func ValidateUEContextReleaseCommand(v *s47.UEContextReleaseCommand, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UEContextReleaseCommand")
	}
	report, err := BridgeValidateUEContextReleaseCommandBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s47.BridgeUEContextReleaseCommandMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextReleaseCommand")
}
func ValidateUEContextReleaseComplete(v *s57.UEContextReleaseComplete, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UEContextReleaseComplete")
	}
	report, err := BridgeValidateUEContextReleaseCompleteBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s57.BridgeUEContextReleaseCompleteMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextReleaseComplete")
}
func ValidateTraceFailureIndication(v *s44.TraceFailureIndication, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "TraceFailureIndication")
	}
	report, err := BridgeValidateTraceFailureIndicationBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s44.BridgeTraceFailureIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "TraceFailureIndication")
}
func ValidateENBDirectInformationTransfer(v *s43.ENBDirectInformationTransfer, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ENBDirectInformationTransfer")
	}
	report, err := BridgeValidateENBDirectInformationTransferBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s43.BridgeENBDirectInformationTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBDirectInformationTransfer")
}
func ValidateMMEDirectInformationTransfer(v *s43.MMEDirectInformationTransfer, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "MMEDirectInformationTransfer")
	}
	report, err := BridgeValidateMMEDirectInformationTransferBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s43.BridgeMMEDirectInformationTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEDirectInformationTransfer")
}
func ValidateKillResponse(v *s42.KillResponse, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "KillResponse")
	}
	report, err := BridgeValidateKillResponseBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s42.BridgeKillResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "KillResponse")
}
func ValidateUplinkUEAssociatedLPPaTransport(v *s55.UplinkUEAssociatedLPPaTransport, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
	}
	report, err := BridgeValidateUplinkUEAssociatedLPPaTransportBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s55.BridgeUplinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UplinkUEAssociatedLPPaTransport")
}
func ValidateUplinkNonUEAssociatedLPPaTransport(v *s55.UplinkNonUEAssociatedLPPaTransport, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
	}
	report, err := BridgeValidateUplinkNonUEAssociatedLPPaTransportBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s55.BridgeUplinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UplinkNonUEAssociatedLPPaTransport")
}
func ValidateUERadioCapabilityMatchRequest(v *s46.UERadioCapabilityMatchRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UERadioCapabilityMatchRequest")
	}
	report, err := BridgeValidateUERadioCapabilityMatchRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeUERadioCapabilityMatchRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UERadioCapabilityMatchRequest")
}
func ValidateUERadioCapabilityMatchResponse(v *s46.UERadioCapabilityMatchResponse, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UERadioCapabilityMatchResponse")
	}
	report, err := BridgeValidateUERadioCapabilityMatchResponseBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeUERadioCapabilityMatchResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UERadioCapabilityMatchResponse")
}
func ValidatePWSRestartIndication(v *s55.PWSRestartIndication, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "PWSRestartIndication")
	}
	report, err := BridgeValidatePWSRestartIndicationBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s55.BridgePWSRestartIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PWSRestartIndication")
}
func ValidateERABModificationIndication(v *s57.ERABModificationIndication, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ERABModificationIndication")
	}
	report, err := BridgeValidateERABModificationIndicationBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s57.BridgeERABModificationIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABModificationIndication")
}
func ValidateUEContextModificationIndication(v *s46.UEContextModificationIndication, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UEContextModificationIndication")
	}
	report, err := BridgeValidateUEContextModificationIndicationBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeUEContextModificationIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextModificationIndication")
}
func ValidateUEContextModificationConfirm(v *s45.UEContextModificationConfirm, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UEContextModificationConfirm")
	}
	report, err := BridgeValidateUEContextModificationConfirmBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s45.BridgeUEContextModificationConfirmMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextModificationConfirm")
}
func ValidateUEContextSuspendRequest(v *s57.UEContextSuspendRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UEContextSuspendRequest")
	}
	report, err := BridgeValidateUEContextSuspendRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s57.BridgeUEContextSuspendRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextSuspendRequest")
}
func ValidateUEContextSuspendResponse(v *s46.UEContextSuspendResponse, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UEContextSuspendResponse")
	}
	report, err := BridgeValidateUEContextSuspendResponseBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeUEContextSuspendResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextSuspendResponse")
}
func ValidateUEContextResumeRequest(v *s48.UEContextResumeRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UEContextResumeRequest")
	}
	report, err := BridgeValidateUEContextResumeRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s48.BridgeUEContextResumeRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextResumeRequest")
}
func ValidateUEContextResumeResponse(v *s49.UEContextResumeResponse, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UEContextResumeResponse")
	}
	report, err := BridgeValidateUEContextResumeResponseBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s49.BridgeUEContextResumeResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextResumeResponse")
}
func ValidateUEContextResumeFailure(v *s46.UEContextResumeFailure, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UEContextResumeFailure")
	}
	report, err := BridgeValidateUEContextResumeFailureBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeUEContextResumeFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextResumeFailure")
}
func ValidateUEInformationTransfer(v *s46.UEInformationTransfer, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UEInformationTransfer")
	}
	report, err := BridgeValidateUEInformationTransferBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeUEInformationTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEInformationTransfer")
}
func ValidateENBCPRelocationIndication(v *s47.ENBCPRelocationIndication, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ENBCPRelocationIndication")
	}
	report, err := BridgeValidateENBCPRelocationIndicationBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s47.BridgeENBCPRelocationIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBCPRelocationIndication")
}
func ValidateSecondaryRATDataUsageReport(v *s57.SecondaryRATDataUsageReport, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "SecondaryRATDataUsageReport")
	}
	report, err := BridgeValidateSecondaryRATDataUsageReportBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s57.BridgeSecondaryRATDataUsageReportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "SecondaryRATDataUsageReport")
}
func ValidateUERadioCapabilityIDMappingRequest(v *s46.UERadioCapabilityIDMappingRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	report, err := BridgeValidateUERadioCapabilityIDMappingRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
}
func ValidateUERadioCapabilityIDMappingResponse(v *s46.UERadioCapabilityIDMappingResponse, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	report, err := BridgeValidateUERadioCapabilityIDMappingResponseBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s46.BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
}
func BridgeWalkValidationAreaScopeOfMDT(v *s41.AreaScopeOfMDT, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.AreaScopeOfMDTChoiceCellBased && v.CellBased != nil {
		s61.BridgeWalkValidationCellBasedMDT(v.CellBased, report, path+".cellBased", false)
	}
	if v.Choice == s00.AreaScopeOfMDTChoiceTABased && v.TABased != nil {
		BridgeWalkValidationTABasedMDT(v.TABased, report, path+".tABased", false)
	}
	if v.Choice == s00.AreaScopeOfMDTChoiceTAIBased && v.TAIBased != nil {
		BridgeWalkValidationTAIBasedMDT(v.TAIBased, report, path+".tAIBased", false)
	}
}
func BridgeWalkValidationAreaScopeOfQMC(v *s41.AreaScopeOfQMC, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.AreaScopeOfQMCChoiceCellBased && v.CellBased != nil {
		s61.BridgeWalkValidationCellBasedQMC(v.CellBased, report, path+".cellBased", false)
	}
	if v.Choice == s00.AreaScopeOfQMCChoiceTABased && v.TABased != nil {
		BridgeWalkValidationTABasedQMC(v.TABased, report, path+".tABased", false)
	}
	if v.Choice == s00.AreaScopeOfQMCChoiceTAIBased && v.TAIBased != nil {
		BridgeWalkValidationTAIBasedQMC(v.TAIBased, report, path+".tAIBased", false)
	}
	if v.Choice == s00.AreaScopeOfQMCChoicePLMNAreaBased && v.PLMNAreaBased != nil {
		s62.BridgeWalkValidationPLMNAreaBasedQMC(v.PLMNAreaBased, report, path+".pLMNAreaBased", false)
	}
}
func BridgeWalkValidationBroadcastCancelledAreaList(v *s41.BroadcastCancelledAreaList, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.BroadcastCancelledAreaListChoiceCellIDCancelled && v.CellIDCancelled != nil {
		s61.BridgeWalkValidationCellIDCancelled(&v.CellIDCancelled, report, path+".cellID-Cancelled", false)
	}
	if v.Choice == s00.BroadcastCancelledAreaListChoiceTAICancelled && v.TAICancelled != nil {
		BridgeWalkValidationTAICancelled(&v.TAICancelled, report, path+".tAI-Cancelled", false)
	}
	if v.Choice == s00.BroadcastCancelledAreaListChoiceEmergencyAreaIDCancelled && v.EmergencyAreaIDCancelled != nil {
		s61.BridgeWalkValidationEmergencyAreaIDCancelled(&v.EmergencyAreaIDCancelled, report, path+".emergencyAreaID-Cancelled", false)
	}
}
func BridgeWalkValidationENBCPRelocationIndication(v *s47.ENBCPRelocationIndication, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s47.ENBCPRelocationIndicationIEs().ENBUES1APID().Info(), s47.ENBCPRelocationIndicationIEs().STMSI().Info(), s47.ENBCPRelocationIndicationIEs().EUTRANCGI().Info(), s47.ENBCPRelocationIndicationIEs().TAI().Info(), s47.ENBCPRelocationIndicationIEs().ULCPSecurityInformation().Info(), s47.ENBCPRelocationIndicationIEs().LTENTNTAIInformation().Info()}
			s30.BridgeMergeNestedValidation(report, s47.BridgeENBCPRelocationIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(96):
				if value, ok := fields[i].Value.AsSTMSI(); ok {
					s62.BridgeWalkValidationSTMSI(value, report, fmt.Sprintf("%s[%d]{id=96}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					s61.BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					s62.BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(254):
				if value, ok := fields[i].Value.AsULCPSecurityInformation(); ok {
					BridgeWalkValidationULCPSecurityInformation(value, report, fmt.Sprintf("%s[%d]{id=254}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					s62.BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBDirectInformationTransfer(v *s43.ENBDirectInformationTransfer, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s43.ENBDirectInformationTransferIEs().InterSystemInformationTransferTypeEDT().Info()}
			s30.BridgeMergeNestedValidation(report, s43.BridgeENBDirectInformationTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABModificationIndication(v *s57.ERABModificationIndication, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s57.ERABModificationIndicationIEs().MMEUES1APID().Info(), s57.ERABModificationIndicationIEs().ENBUES1APID().Info(), s57.ERABModificationIndicationIEs().ERABToBeModifiedListBearerModInd().Info(), s57.ERABModificationIndicationIEs().ERABNotToBeModifiedListBearerModInd().Info(), s57.ERABModificationIndicationIEs().CSGMembershipInfo().Info(), s57.ERABModificationIndicationIEs().TunnelInformationForBBF().Info(), s57.ERABModificationIndicationIEs().SecondaryRATDataUsageReportList().Info(), s57.ERABModificationIndicationIEs().UserLocationInformation().Info()}
			s30.BridgeMergeNestedValidation(report, s57.BridgeERABModificationIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(199):
				if value, ok := fields[i].Value.AsERABToBeModifiedListBearerModInd(); ok {
					s61.BridgeWalkValidationERABToBeModifiedListBearerModInd(value, report, fmt.Sprintf("%s[%d]{id=199}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(201):
				if value, ok := fields[i].Value.AsERABNotToBeModifiedListBearerModInd(); ok {
					s61.BridgeWalkValidationERABNotToBeModifiedListBearerModInd(value, report, fmt.Sprintf("%s[%d]{id=201}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(226):
				if value, ok := fields[i].Value.AsCSGMembershipInfo(); ok {
					s61.BridgeWalkValidationCSGMembershipInfo(value, report, fmt.Sprintf("%s[%d]{id=226}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(176):
				if value, ok := fields[i].Value.AsTunnelInformationForBBF(); ok {
					BridgeWalkValidationTunnelInformation(value, report, fmt.Sprintf("%s[%d]{id=176}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s62.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABModifyRequest(v *s51.ERABModifyRequest, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s51.ERABModifyRequestIEs().MMEUES1APID().Info(), s51.ERABModifyRequestIEs().ENBUES1APID().Info(), s51.ERABModifyRequestIEs().UEaggregateMaximumBitrate().Info(), s51.ERABModifyRequestIEs().ERABToBeModifiedListBearerModReq().Info(), s51.ERABModifyRequestIEs().SecondaryRATDataUsageRequest().Info()}
			s30.BridgeMergeNestedValidation(report, s51.BridgeERABModifyRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABModifyResponse(v *s57.ERABModifyResponse, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s57.ERABModifyResponseIEs().MMEUES1APID().Info(), s57.ERABModifyResponseIEs().ENBUES1APID().Info(), s57.ERABModifyResponseIEs().ERABModifyListBearerModRes().Info(), s57.ERABModifyResponseIEs().ERABFailedToModifyList().Info(), s57.ERABModifyResponseIEs().CriticalityDiagnostics().Info(), s57.ERABModifyResponseIEs().SecondaryRATDataUsageReportList().Info(), s57.ERABModifyResponseIEs().UserLocationInformation().Info()}
			s30.BridgeMergeNestedValidation(report, s57.BridgeERABModifyResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(31):
				if value, ok := fields[i].Value.AsERABModifyListBearerModRes(); ok {
					s61.BridgeWalkValidationERABModifyListBearerModRes(value, report, fmt.Sprintf("%s[%d]{id=31}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(32):
				if value, ok := fields[i].Value.AsERABFailedToModifyList(); ok {
					s61.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=32}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s62.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABReleaseCommand(v *s49.ERABReleaseCommand, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s49.ERABReleaseCommandIEs().MMEUES1APID().Info(), s49.ERABReleaseCommandIEs().ENBUES1APID().Info(), s49.ERABReleaseCommandIEs().UEaggregateMaximumBitrate().Info(), s49.ERABReleaseCommandIEs().ERABToBeReleasedList().Info(), s49.ERABReleaseCommandIEs().NASPDU().Info()}
			s30.BridgeMergeNestedValidation(report, s49.BridgeERABReleaseCommandIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(33):
				if value, ok := fields[i].Value.AsERABToBeReleasedList(); ok {
					s61.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=33}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABReleaseIndication(v *s57.ERABReleaseIndication, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s57.ERABReleaseIndicationIEs().MMEUES1APID().Info(), s57.ERABReleaseIndicationIEs().ENBUES1APID().Info(), s57.ERABReleaseIndicationIEs().ERABReleasedList().Info(), s57.ERABReleaseIndicationIEs().UserLocationInformation().Info(), s57.ERABReleaseIndicationIEs().SecondaryRATDataUsageReportList().Info()}
			s30.BridgeMergeNestedValidation(report, s57.BridgeERABReleaseIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(110):
				if value, ok := fields[i].Value.AsERABReleasedList(); ok {
					s61.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=110}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s62.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABReleaseResponse(v *s57.ERABReleaseResponse, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s57.ERABReleaseResponseIEs().MMEUES1APID().Info(), s57.ERABReleaseResponseIEs().ENBUES1APID().Info(), s57.ERABReleaseResponseIEs().ERABReleaseListBearerRelComp().Info(), s57.ERABReleaseResponseIEs().ERABFailedToReleaseList().Info(), s57.ERABReleaseResponseIEs().CriticalityDiagnostics().Info(), s57.ERABReleaseResponseIEs().UserLocationInformation().Info(), s57.ERABReleaseResponseIEs().SecondaryRATDataUsageReportList().Info()}
			s30.BridgeMergeNestedValidation(report, s57.BridgeERABReleaseResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(69):
				if value, ok := fields[i].Value.AsERABReleaseListBearerRelComp(); ok {
					s61.BridgeWalkValidationERABReleaseListBearerRelComp(value, report, fmt.Sprintf("%s[%d]{id=69}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(34):
				if value, ok := fields[i].Value.AsERABFailedToReleaseList(); ok {
					s61.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=34}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s62.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABSetupRequest(v *s51.ERABSetupRequest, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s51.ERABSetupRequestIEs().MMEUES1APID().Info(), s51.ERABSetupRequestIEs().ENBUES1APID().Info(), s51.ERABSetupRequestIEs().UEaggregateMaximumBitrate().Info(), s51.ERABSetupRequestIEs().ERABToBeSetupListBearerSUReq().Info()}
			s30.BridgeMergeNestedValidation(report, s51.BridgeERABSetupRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(16):
				if value, ok := fields[i].Value.AsERABToBeSetupListBearerSUReq(); ok {
					s62.BridgeWalkValidationERABToBeSetupListBearerSUReq(value, report, fmt.Sprintf("%s[%d]{id=16}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABSetupResponse(v *s57.ERABSetupResponse, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s57.ERABSetupResponseIEs().MMEUES1APID().Info(), s57.ERABSetupResponseIEs().ENBUES1APID().Info(), s57.ERABSetupResponseIEs().ERABSetupListBearerSURes().Info(), s57.ERABSetupResponseIEs().ERABFailedToSetupListBearerSURes().Info(), s57.ERABSetupResponseIEs().CriticalityDiagnostics().Info(), s57.ERABSetupResponseIEs().UserLocationInformation().Info()}
			s30.BridgeMergeNestedValidation(report, s57.BridgeERABSetupResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(28):
				if value, ok := fields[i].Value.AsERABSetupListBearerSURes(); ok {
					s61.BridgeWalkValidationERABSetupListBearerSURes(value, report, fmt.Sprintf("%s[%d]{id=28}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(29):
				if value, ok := fields[i].Value.AsERABFailedToSetupListBearerSURes(); ok {
					s61.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=29}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeModifiedItemBearerModReq(v *s29.ERABToBeModifiedItemBearerModReq, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s61.BridgeWalkValidationERABLevelQoSParameters(&v.ERABLevelQoSParameters, report, path+".e-RABLevelQoSParameters", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s24.ERABToBeModifyItemBearerModReqExtIEs().TransportInformation().Info())}
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABToBeModifyItemBearerModReqExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
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
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeModifiedListBearerModReq(v *s29.ERABToBeModifiedListBearerModReq, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s25.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s29.ERABToBeModifiedItemBearerModReqIEs().ERABToBeModifiedItemBearerModReq().Info()}
		s30.BridgeMergeNestedValidation(report, s33.BridgeERABToBeModifiedItemBearerModReqIEValueValidateS1APIEContainer(s29.ERABToBeModifiedItemBearerModReqIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s29.ERABToBeModifiedItemBearerModReqIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
func BridgeWalkValidationFailureEventReport(v *s24.FailureEventReport, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.FailureEventReportChoiceTooEarlyInterRATHOReportFromEUTRAN && v.TooEarlyInterRATHOReportFromEUTRAN != nil {
		BridgeWalkValidationTooEarlyInterRATHOReportReportFromEUTRAN(v.TooEarlyInterRATHOReportFromEUTRAN, report, path+".tooEarlyInterRATHOReportFromEUTRAN", false)
	}
}
func BridgeWalkValidationHandoverNotify(v *s44.HandoverNotify, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s44.HandoverNotifyIEs().MMEUES1APID().Info(), s44.HandoverNotifyIEs().ENBUES1APID().Info(), s44.HandoverNotifyIEs().EUTRANCGI().Info(), s44.HandoverNotifyIEs().TAI().Info(), s44.HandoverNotifyIEs().TunnelInformationForBBF().Info(), s44.HandoverNotifyIEs().LHNID().Info(), s44.HandoverNotifyIEs().PSCellInformation().Info(), s44.HandoverNotifyIEs().NotifySourceeNB().Info(), s44.HandoverNotifyIEs().LTENTNTAIInformation().Info()}
			s30.BridgeMergeNestedValidation(report, s45.BridgeHandoverNotifyIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					s61.BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					s62.BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(176):
				if value, ok := fields[i].Value.AsTunnelInformationForBBF(); ok {
					BridgeWalkValidationTunnelInformation(value, report, fmt.Sprintf("%s[%d]{id=176}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(288):
				if value, ok := fields[i].Value.AsPSCellInformation(); ok {
					s62.BridgeWalkValidationPSCellInformation(value, report, fmt.Sprintf("%s[%d]{id=288}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					s62.BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverRequired(v *s43.HandoverRequired, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s43.HandoverRequiredIEs().MMEUES1APID().Info(), s43.HandoverRequiredIEs().ENBUES1APID().Info(), s43.HandoverRequiredIEs().HandoverType().Info(), s43.HandoverRequiredIEs().Cause().Info(), s43.HandoverRequiredIEs().TargetID().Info(), s43.HandoverRequiredIEs().DirectForwardingPathAvailability().Info(), s43.HandoverRequiredIEs().SRVCCHOIndication().Info(), s43.HandoverRequiredIEs().SourceToTargetTransparentContainer().Info(), s43.HandoverRequiredIEs().SourceToTargetTransparentContainerSecondary().Info(), s43.HandoverRequiredIEs().MSClassmark2().Info(), s43.HandoverRequiredIEs().MSClassmark3().Info(), s43.HandoverRequiredIEs().CSGId().Info(), s43.HandoverRequiredIEs().CellAccessMode().Info(), s43.HandoverRequiredIEs().PSServiceNotAvailable().Info()}
			s30.BridgeMergeNestedValidation(report, s43.BridgeHandoverRequiredIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s61.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(4):
				if value, ok := fields[i].Value.AsTargetID(); ok {
					BridgeWalkValidationTargetID(value, report, fmt.Sprintf("%s[%d]{id=4}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInitialUEMessage(v *s45.InitialUEMessage, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s44.InitialUEMessageIEs().ENBUES1APID().Info(), s44.InitialUEMessageIEs().NASPDU().Info(), s44.InitialUEMessageIEs().TAI().Info(), s44.InitialUEMessageIEs().EUTRANCGI().Info(), s44.InitialUEMessageIEs().RRCEstablishmentCause().Info(), s44.InitialUEMessageIEs().STMSI().Info(), s44.InitialUEMessageIEs().CSGId().Info(), s44.InitialUEMessageIEs().GUMMEIID().Info(), s44.InitialUEMessageIEs().CellAccessMode().Info(), s44.InitialUEMessageIEs().GWTransportLayerAddress().Info(), s44.InitialUEMessageIEs().RelayNodeIndicator().Info(), s44.InitialUEMessageIEs().GUMMEIType().Info(), s44.InitialUEMessageIEs().TunnelInformationForBBF().Info(), s44.InitialUEMessageIEs().SIPTOLGWTransportLayerAddress().Info(), s44.InitialUEMessageIEs().LHNID().Info(), s44.InitialUEMessageIEs().MMEGroupID().Info(), s44.InitialUEMessageIEs().UEUsageType().Info(), s44.InitialUEMessageIEs().CEModeBSupportIndicator().Info(), s44.InitialUEMessageIEs().DCNID().Info(), s44.InitialUEMessageIEs().CoverageLevel().Info(), s44.InitialUEMessageIEs().UEApplicationLayerMeasurementCapability().Info(), s44.InitialUEMessageIEs().EDTSession().Info(), s44.InitialUEMessageIEs().IABNodeIndication().Info(), s44.InitialUEMessageIEs().LTENTNTAIInformation().Info(), s44.InitialUEMessageIEs().CoarseUELocationRequested().Info()}
			s30.BridgeMergeNestedValidation(report, s45.BridgeInitialUEMessageIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					s62.BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					s61.BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(96):
				if value, ok := fields[i].Value.AsSTMSI(); ok {
					s62.BridgeWalkValidationSTMSI(value, report, fmt.Sprintf("%s[%d]{id=96}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(75):
				if value, ok := fields[i].Value.AsGUMMEIID(); ok {
					s61.BridgeWalkValidationGUMMEI(value, report, fmt.Sprintf("%s[%d]{id=75}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(176):
				if value, ok := fields[i].Value.AsTunnelInformationForBBF(); ok {
					BridgeWalkValidationTunnelInformation(value, report, fmt.Sprintf("%s[%d]{id=176}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					s62.BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInterSystemInformationTransferType(v *s43.InterSystemInformationTransferType, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.InterSystemInformationTransferTypeChoiceRIMTransfer && v.RIMTransfer != nil {
		BridgeWalkValidationRIMTransfer(v.RIMTransfer, report, path+".rIMTransfer", false)
	}
}
func BridgeWalkValidationKillResponse(v *s42.KillResponse, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s41.KillResponseIEs().MessageIdentifier().Info(), s41.KillResponseIEs().SerialNumber().Info(), s41.KillResponseIEs().BroadcastCancelledAreaList().Info(), s41.KillResponseIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s42.BridgeKillResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(141):
				if value, ok := fields[i].Value.AsBroadcastCancelledAreaList(); ok {
					BridgeWalkValidationBroadcastCancelledAreaList(value, report, fmt.Sprintf("%s[%d]{id=141}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMMEDirectInformationTransfer(v *s43.MMEDirectInformationTransfer, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s43.MMEDirectInformationTransferIEs().InterSystemInformationTransferTypeMDT().Info()}
			s30.BridgeMergeNestedValidation(report, s43.BridgeMMEDirectInformationTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPWSRestartIndication(v *s55.PWSRestartIndication, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s55.PWSRestartIndicationIEs().ECGIListForRestart().Info(), s55.PWSRestartIndicationIEs().GlobalENBID().Info(), s55.PWSRestartIndicationIEs().TAIListForRestart().Info(), s55.PWSRestartIndicationIEs().EmergencyAreaIDListForRestart().Info()}
			s30.BridgeMergeNestedValidation(report, s55.BridgePWSRestartIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(182):
				if value, ok := fields[i].Value.AsECGIListForRestart(); ok {
					s61.BridgeWalkValidationECGIListForRestart(value, report, fmt.Sprintf("%s[%d]{id=182}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(59):
				if value, ok := fields[i].Value.AsGlobalENBID(); ok {
					s61.BridgeWalkValidationGlobalENBID(value, report, fmt.Sprintf("%s[%d]{id=59}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(188):
				if value, ok := fields[i].Value.AsTAIListForRestart(); ok {
					BridgeWalkValidationTAIListForRestart(value, report, fmt.Sprintf("%s[%d]{id=188}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(190):
				if value, ok := fields[i].Value.AsEmergencyAreaIDListForRestart(); ok {
					s61.BridgeWalkValidationEmergencyAreaIDListForRestart(value, report, fmt.Sprintf("%s[%d]{id=190}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPathSwitchRequest(v *s51.PathSwitchRequest, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s51.PathSwitchRequestIEs().ENBUES1APID().Info(), s51.PathSwitchRequestIEs().ERABToBeSwitchedDLList().Info(), s51.PathSwitchRequestIEs().SourceMMEUES1APID().Info(), s51.PathSwitchRequestIEs().EUTRANCGI().Info(), s51.PathSwitchRequestIEs().TAI().Info(), s51.PathSwitchRequestIEs().UESecurityCapabilities().Info(), s51.PathSwitchRequestIEs().CSGId().Info(), s51.PathSwitchRequestIEs().CellAccessMode().Info(), s51.PathSwitchRequestIEs().SourceMMEGUMMEI().Info(), s51.PathSwitchRequestIEs().CSGMembershipStatus().Info(), s51.PathSwitchRequestIEs().TunnelInformationForBBF().Info(), s51.PathSwitchRequestIEs().LHNID().Info(), s51.PathSwitchRequestIEs().RRCResumeCause().Info(), s51.PathSwitchRequestIEs().NRUESecurityCapabilities().Info(), s51.PathSwitchRequestIEs().PSCellInformation().Info(), s51.PathSwitchRequestIEs().LTENTNTAIInformation().Info()}
			s30.BridgeMergeNestedValidation(report, s51.BridgePathSwitchRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(22):
				if value, ok := fields[i].Value.AsERABToBeSwitchedDLList(); ok {
					s62.BridgeWalkValidationERABToBeSwitchedDLList(value, report, fmt.Sprintf("%s[%d]{id=22}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					s61.BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					s62.BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(107):
				if value, ok := fields[i].Value.AsUESecurityCapabilities(); ok {
					BridgeWalkValidationUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=107}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(157):
				if value, ok := fields[i].Value.AsSourceMMEGUMMEI(); ok {
					s61.BridgeWalkValidationGUMMEI(value, report, fmt.Sprintf("%s[%d]{id=157}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(176):
				if value, ok := fields[i].Value.AsTunnelInformationForBBF(); ok {
					BridgeWalkValidationTunnelInformation(value, report, fmt.Sprintf("%s[%d]{id=176}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(269):
				if value, ok := fields[i].Value.AsNRUESecurityCapabilities(); ok {
					s62.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(288):
				if value, ok := fields[i].Value.AsPSCellInformation(); ok {
					s62.BridgeWalkValidationPSCellInformation(value, report, fmt.Sprintf("%s[%d]{id=288}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					s62.BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPathSwitchRequestAcknowledge(v *s58.PathSwitchRequestAcknowledge, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s58.PathSwitchRequestAcknowledgeIEs().MMEUES1APID().Info(), s58.PathSwitchRequestAcknowledgeIEs().ENBUES1APID().Info(), s58.PathSwitchRequestAcknowledgeIEs().UEaggregateMaximumBitrate().Info(), s58.PathSwitchRequestAcknowledgeIEs().ERABToBeSwitchedULList().Info(), s58.PathSwitchRequestAcknowledgeIEs().ERABToBeReleasedList().Info(), s58.PathSwitchRequestAcknowledgeIEs().SecurityContext().Info(), s58.PathSwitchRequestAcknowledgeIEs().CriticalityDiagnostics().Info(), s58.PathSwitchRequestAcknowledgeIEs().MMEUES1APID2().Info(), s58.PathSwitchRequestAcknowledgeIEs().CSGMembershipStatus().Info(), s58.PathSwitchRequestAcknowledgeIEs().ProSeAuthorized().Info(), s58.PathSwitchRequestAcknowledgeIEs().UEUserPlaneCIoTSupportIndicator().Info(), s58.PathSwitchRequestAcknowledgeIEs().V2XServicesAuthorized().Info(), s58.PathSwitchRequestAcknowledgeIEs().UESidelinkAggregateMaximumBitrate().Info(), s58.PathSwitchRequestAcknowledgeIEs().EnhancedCoverageRestricted().Info(), s58.PathSwitchRequestAcknowledgeIEs().NRUESecurityCapabilities().Info(), s58.PathSwitchRequestAcknowledgeIEs().CEModeBRestricted().Info(), s58.PathSwitchRequestAcknowledgeIEs().AerialUEsubscriptionInformation().Info(), s58.PathSwitchRequestAcknowledgeIEs().PendingDataIndication().Info(), s58.PathSwitchRequestAcknowledgeIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s58.PathSwitchRequestAcknowledgeIEs().HandoverRestrictionList().Info(), s58.PathSwitchRequestAcknowledgeIEs().AdditionalRRMPriorityIndex().Info(), s58.PathSwitchRequestAcknowledgeIEs().NRV2XServicesAuthorized().Info(), s58.PathSwitchRequestAcknowledgeIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s58.PathSwitchRequestAcknowledgeIEs().PC5QoSParameters().Info(), s58.PathSwitchRequestAcknowledgeIEs().UERadioCapabilityID().Info(), s58.PathSwitchRequestAcknowledgeIEs().UESecurityCapabilities().Info(), s58.PathSwitchRequestAcknowledgeIEs().ERABToBeUpdatedList().Info(), s58.PathSwitchRequestAcknowledgeIEs().TimeRefDistribution().Info()}
			s30.BridgeMergeNestedValidation(report, s58.BridgePathSwitchRequestAcknowledgeIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(95):
				if value, ok := fields[i].Value.AsERABToBeSwitchedULList(); ok {
					s61.BridgeWalkValidationERABToBeSwitchedULList(value, report, fmt.Sprintf("%s[%d]{id=95}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(33):
				if value, ok := fields[i].Value.AsERABToBeReleasedList(); ok {
					s61.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=33}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(40):
				if value, ok := fields[i].Value.AsSecurityContext(); ok {
					s62.BridgeWalkValidationSecurityContext(value, report, fmt.Sprintf("%s[%d]{id=40}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(195):
				if value, ok := fields[i].Value.AsProSeAuthorized(); ok {
					s62.BridgeWalkValidationProSeAuthorized(value, report, fmt.Sprintf("%s[%d]{id=195}", nestedPath, i), false)
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
					s62.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					s62.BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(41):
				if value, ok := fields[i].Value.AsHandoverRestrictionList(); ok {
					s62.BridgeWalkValidationHandoverRestrictionList(value, report, fmt.Sprintf("%s[%d]{id=41}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(306):
				if value, ok := fields[i].Value.AsNRV2XServicesAuthorized(); ok {
					s62.BridgeWalkValidationNRV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=306}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(307):
				if value, ok := fields[i].Value.AsNRUESidelinkAggregateMaximumBitrate(); ok {
					s62.BridgeWalkValidationNRUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=307}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(308):
				if value, ok := fields[i].Value.AsPC5QoSParameters(); ok {
					s62.BridgeWalkValidationPC5QoSParameters(value, report, fmt.Sprintf("%s[%d]{id=308}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(107):
				if value, ok := fields[i].Value.AsUESecurityCapabilities(); ok {
					BridgeWalkValidationUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=107}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(341):
				if value, ok := fields[i].Value.AsERABToBeUpdatedList(); ok {
					s62.BridgeWalkValidationERABToBeUpdatedList(value, report, fmt.Sprintf("%s[%d]{id=341}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRIMRoutingAddress(v *s42.RIMRoutingAddress, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.RIMRoutingAddressChoiceGERANCellID && v.GERANCellID != nil {
		s62.BridgeWalkValidationGERANCellID(v.GERANCellID, report, path+".gERAN-Cell-ID", false)
	}
	if v.Choice == s00.RIMRoutingAddressChoiceTargetRNCID && v.TargetRNCID != nil {
		BridgeWalkValidationTargetRNCID(v.TargetRNCID, report, path+".targetRNC-ID", false)
	}
}
func BridgeWalkValidationRIMTransfer(v *s43.RIMTransfer, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.RIMRoutingAddress != nil {
		BridgeWalkValidationRIMRoutingAddress(v.RIMRoutingAddress, report, path+".rIMRoutingAddress", false)
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s35.BridgeRIMTransferExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationReset(v *s45.Reset, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s45.ResetIEs().Cause().Info(), s45.ResetIEs().ResetType().Info()}
			s30.BridgeMergeNestedValidation(report, s45.BridgeResetIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s61.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(92):
				if value, ok := fields[i].Value.AsResetType(); ok {
					BridgeWalkValidationResetType(value, report, fmt.Sprintf("%s[%d]{id=92}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResetAcknowledge(v *s55.ResetAcknowledge, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s55.ResetAcknowledgeIEs().UEAssociatedLogicalS1ConnectionListResAck().Info(), s55.ResetAcknowledgeIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s55.BridgeResetAcknowledgeIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(93):
				if value, ok := fields[i].Value.AsUEAssociatedLogicalS1ConnectionListResAck(); ok {
					BridgeWalkValidationUEAssociatedLogicalS1ConnectionListResAck(value, report, fmt.Sprintf("%s[%d]{id=93}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResetType(v *s45.ResetType, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.ResetTypeChoicePartOfS1Interface && v.PartOfS1Interface != nil {
		BridgeWalkValidationUEAssociatedLogicalS1ConnectionListRes(&v.PartOfS1Interface, report, path+".partOfS1-Interface", false)
	}
}
func BridgeWalkValidationSONtransferRequestContainer(v *s28.SONtransferRequestContainer, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.SONtransferRequestContainerChoiceMultiCellLoadReporting && v.MultiCellLoadReporting != nil {
		s62.BridgeWalkValidationMultiCellLoadReportingRequest(v.MultiCellLoadReporting, report, path+".multiCellLoadReporting", false)
	}
	if v.Choice == s00.SONtransferRequestContainerChoiceEventTriggeredCellLoadReporting && v.EventTriggeredCellLoadReporting != nil {
		s61.BridgeWalkValidationEventTriggeredCellLoadReportingRequest(v.EventTriggeredCellLoadReporting, report, path+".eventTriggeredCellLoadReporting", false)
	}
	if v.Choice == s00.SONtransferRequestContainerChoiceHOReporting && v.HOReporting != nil {
		s61.BridgeWalkValidationHOReport(v.HOReporting, report, path+".hOReporting", false)
	}
	if v.Choice == s00.SONtransferRequestContainerChoiceEutranCellActivation && v.EutranCellActivation != nil {
		s61.BridgeWalkValidationCellActivationRequest(v.EutranCellActivation, report, path+".eutranCellActivation", false)
	}
	if v.Choice == s00.SONtransferRequestContainerChoiceEnergySavingsIndication && v.EnergySavingsIndication != nil {
		s62.BridgeWalkValidationCellStateIndication(v.EnergySavingsIndication, report, path+".energySavingsIndication", false)
	}
	if v.Choice == s00.SONtransferRequestContainerChoiceFailureEventReporting && v.FailureEventReporting != nil {
		BridgeWalkValidationFailureEventReport(v.FailureEventReporting, report, path+".failureEventReporting", false)
	}
}
func BridgeWalkValidationSecondaryRATDataUsageReport(v *s57.SecondaryRATDataUsageReport, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s57.SecondaryRATDataUsageReportIEs().MMEUES1APID().Info(), s57.SecondaryRATDataUsageReportIEs().ENBUES1APID().Info(), s57.SecondaryRATDataUsageReportIEs().SecondaryRATDataUsageReportList().Info(), s57.SecondaryRATDataUsageReportIEs().HandoverFlag().Info(), s57.SecondaryRATDataUsageReportIEs().UserLocationInformation().Info(), s57.SecondaryRATDataUsageReportIEs().TimeSinceSecondaryNodeRelease().Info()}
			s30.BridgeMergeNestedValidation(report, s57.BridgeSecondaryRATDataUsageReportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s62.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSourceeNBToTargeteNBTransparentContainer(v *s52.SourceeNBToTargeteNBTransparentContainer, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.ERABInformationList != nil {
		s62.BridgeWalkValidationERABInformationList(&v.ERABInformationList, report, path+".e-RABInformationList", false)
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s61.BridgeWalkValidationEUTRANCGI(&v.TargetCellID, report, path+".targetCell-ID", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationUEHistoryInformation(&v.UEHistoryInformation, report, path+".uE-HistoryInformation", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s44.SourceeNBToTargeteNBTransparentContainerExtIEs().MobilityInformation().Info()), s00.FieldInfo(s44.SourceeNBToTargeteNBTransparentContainerExtIEs().UEHistoryInformationFromTheUE().Info()), s00.FieldInfo(s44.SourceeNBToTargeteNBTransparentContainerExtIEs().IMSvoiceEPSfallbackfrom5G().Info()), s00.FieldInfo(s44.SourceeNBToTargeteNBTransparentContainerExtIEs().AdditionalRRMPriorityIndex().Info()), s00.FieldInfo(s44.SourceeNBToTargeteNBTransparentContainerExtIEs().ContextatSource().Info()), s00.FieldInfo(s44.SourceeNBToTargeteNBTransparentContainerExtIEs().IntersystemMeasurementConfiguration().Info()), s00.FieldInfo(s44.SourceeNBToTargeteNBTransparentContainerExtIEs().SourceNodeID().Info()), s00.FieldInfo(s44.SourceeNBToTargeteNBTransparentContainerExtIEs().EmergencyIndicator().Info()), s00.FieldInfo(s44.SourceeNBToTargeteNBTransparentContainerExtIEs().UEContextReferenceatSourceeNB().Info()), s00.FieldInfo(s44.SourceeNBToTargeteNBTransparentContainerExtIEs().SourceSNID().Info()), s00.FieldInfo(s44.SourceeNBToTargeteNBTransparentContainerExtIEs().DirectForwardingPathAvailability().Info()), s00.FieldInfo(s44.SourceeNBToTargeteNBTransparentContainerExtIEs().TimeBasedHandoverInformation().Info())}
				s30.BridgeMergeNestedValidation(report, s44.BridgeSourceeNBToTargeteNBTransparentContainerExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(300):
					if value, ok := fields[i].ExtensionValue.AsContextatSource(); ok {
						s62.BridgeWalkValidationContextatSource(value, report, fmt.Sprintf("%s[%d]{id=300}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(311):
					if value, ok := fields[i].ExtensionValue.AsIntersystemMeasurementConfiguration(); ok {
						s62.BridgeWalkValidationIntersystemMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=311}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(312):
					if value, ok := fields[i].ExtensionValue.AsSourceNodeID(); ok {
						s62.BridgeWalkValidationSourceNodeID(value, report, fmt.Sprintf("%s[%d]{id=312}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(343):
					if value, ok := fields[i].ExtensionValue.AsSourceSNID(); ok {
						s62.BridgeWalkValidationGlobalRANNODEID(value, report, fmt.Sprintf("%s[%d]{id=343}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(350):
					if value, ok := fields[i].ExtensionValue.AsTimeBasedHandoverInformation(); ok {
						BridgeWalkValidationTimeBasedHandoverInformation(value, report, fmt.Sprintf("%s[%d]{id=350}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTABasedMDT(v *s40.TABasedMDT, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAListforMDT(&v.TAListforMDT, report, path+".tAListforMDT", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s40.BridgeTABasedMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTABasedQMC(v *s40.TABasedQMC, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAListforQMC(&v.TAListforQMC, report, path+".tAListforQMC", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s40.BridgeTABasedQMCExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAIBasedMDT(v *s41.TAIBasedMDT, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAIListforMDT(&v.TAIListforMDT, report, path+".tAIListforMDT", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s40.BridgeTAIBasedMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAIBasedQMC(v *s41.TAIBasedQMC, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAIListforQMC(&v.TAIListforQMC, report, path+".tAIListforQMC", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s40.BridgeTAIBasedQMCExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAICancelled(v *s41.TAICancelled, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s25.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationTAICancelledItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAICancelledItem(v *s41.TAICancelledItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s62.BridgeWalkValidationTAI(&v.TAI, report, path+".tAI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s61.BridgeWalkValidationCancelledCellinTAI(&v.CancelledCellinTAI, report, path+".cancelledCellinTAI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s40.BridgeTAICancelledItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAIItem(v *s42.TAIItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s62.BridgeWalkValidationTAI(&v.TAI, report, path+".tAI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s42.BridgeTAIItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTAIList(v *s42.TAIList, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s25.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s42.TAIItemIEs().TAIItem().Info()}
		s30.BridgeMergeNestedValidation(report, s42.BridgeTAIItemIEValueValidateS1APIEContainer(s42.TAIItemIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s42.TAIItemIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
func BridgeWalkValidationTAIListForRestart(v *s41.TAIListForRestart, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s25.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		s62.BridgeWalkValidationTAI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAIListforMDT(v *s41.TAIListforMDT, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s25.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		s62.BridgeWalkValidationTAI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAIListforQMC(v *s41.TAIListforQMC, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s25.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		s62.BridgeWalkValidationTAI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAIListforWarning(v *s41.TAIListforWarning, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s25.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		s62.BridgeWalkValidationTAI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAListforMDT(v *s00.TAListforMDT, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationTAListforQMC(v *s00.TAListforQMC, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationTargetID(v *s43.TargetID, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
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
		s61.BridgeWalkValidationCGI(v.CGI, report, path+".cGI", false)
	}
	if v.Choice == s00.TargetIDChoiceTargetgNgRanNodeID && v.TargetgNgRanNodeID != nil {
		BridgeWalkValidationTargetNgRanNodeID(v.TargetgNgRanNodeID, report, path+".targetgNgRanNode-ID", false)
	}
}
func BridgeWalkValidationTargetNgRanNodeID(v *s42.TargetNgRanNodeID, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s62.BridgeWalkValidationGlobalRANNODEID(&v.GlobalRANNODEID, report, path+".global-RAN-NODE-ID", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s61.BridgeWalkValidationFiveGSTAI(&v.SelectedTAI, report, path+".selected-TAI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s42.BridgeTargetNgRanNodeIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTargetRNCID(v *s42.TargetRNCID, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s62.BridgeWalkValidationLAI(&v.LAI, report, path+".lAI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s43.BridgeTargetRNCIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTargeteNBID(v *s43.TargeteNBID, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s61.BridgeWalkValidationGlobalENBID(&v.GlobalENBID, report, path+".global-ENB-ID", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s62.BridgeWalkValidationTAI(&v.SelectedTAI, report, path+".selected-TAI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s43.BridgeTargeteNBIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTargeteNBToSourceeNBTransparentContainer(v *s50.TargeteNBToSourceeNBTransparentContainer, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s50.TargeteNBToSourceeNBTransparentContainerExtIEs().DAPSResponseInfoList().Info()), s00.FieldInfo(s50.TargeteNBToSourceeNBTransparentContainerExtIEs().RACSIndication().Info()), s00.FieldInfo(s50.TargeteNBToSourceeNBTransparentContainerExtIEs().ERABSecurityResultList().Info()), s00.FieldInfo(s50.TargeteNBToSourceeNBTransparentContainerExtIEs().DirectForwardingPathAvailability().Info())}
				s30.BridgeMergeNestedValidation(report, s50.BridgeTargeteNBToSourceeNBTransparentContainerExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(318):
					if value, ok := fields[i].ExtensionValue.AsDAPSResponseInfoList(); ok {
						s61.BridgeWalkValidationDAPSResponseInfoList(value, report, fmt.Sprintf("%s[%d]{id=318}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(335):
					if value, ok := fields[i].ExtensionValue.AsERABSecurityResultList(); ok {
						s62.BridgeWalkValidationERABSecurityResultList(value, report, fmt.Sprintf("%s[%d]{id=335}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTimeBasedHandoverInformation(v *s43.TimeBasedHandoverInformation, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s44.BridgeTimeBasedHandoverInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTimeSynchronisationInfo(v *s44.TimeSynchronisationInfo, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s14.TimeSynchronisationInfoExtIEs().MutingAvailabilityIndication().Info())}
				s30.BridgeMergeNestedValidation(report, s44.BridgeTimeSynchronisationInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTooEarlyInterRATHOReportReportFromEUTRAN(v *s24.TooEarlyInterRATHOReportReportFromEUTRAN, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTraceFailureIndication(v *s44.TraceFailureIndication, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s24.TraceFailureIndicationIEs().MMEUES1APID().Info(), s24.TraceFailureIndicationIEs().ENBUES1APID().Info(), s24.TraceFailureIndicationIEs().EUTRANTraceID().Info(), s24.TraceFailureIndicationIEs().Cause().Info()}
			s30.BridgeMergeNestedValidation(report, s44.BridgeTraceFailureIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s61.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTransportInformation(v *s24.TransportInformation, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTunnelInformation(v *s44.TunnelInformation, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s45.BridgeTunnelInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEAggregateMaximumBitrate(v *s45.UEAggregateMaximumBitrate, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s14.UEAggregateMaximumBitratesExtIEs().ExtendedUEaggregateMaximumBitRateDL().Info()), s00.FieldInfo(s14.UEAggregateMaximumBitratesExtIEs().ExtendedUEaggregateMaximumBitRateUL().Info())}
				s30.BridgeMergeNestedValidation(report, s45.BridgeUEAggregateMaximumBitratesExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEAppLayerMeasConfig(v *s45.UEAppLayerMeasConfig, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationAreaScopeOfQMC(&v.AreaScopeOfQMC, report, path+".areaScopeOfQMC", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s14.UEAppLayerMeasConfigExtIEs().ServiceType().Info())}
				s30.BridgeMergeNestedValidation(report, s45.BridgeUEAppLayerMeasConfigExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEAssociatedLogicalS1ConnectionItem(v *s45.UEAssociatedLogicalS1ConnectionItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s45.BridgeUEAssociatedLogicalS1ConnectionItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEAssociatedLogicalS1ConnectionListRes(v *s45.UEAssociatedLogicalS1ConnectionListRes, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s25.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s45.UEAssociatedLogicalS1ConnectionItemRes().UEAssociatedLogicalS1ConnectionItem().Info()}
		s30.BridgeMergeNestedValidation(report, s45.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueValidateS1APIEContainer(s45.UEAssociatedLogicalS1ConnectionItemResIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s45.UEAssociatedLogicalS1ConnectionItemResIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
func BridgeWalkValidationUEAssociatedLogicalS1ConnectionListResAck(v *s45.UEAssociatedLogicalS1ConnectionListResAck, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s25.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s45.UEAssociatedLogicalS1ConnectionItemResAck().UEAssociatedLogicalS1ConnectionItem().Info()}
		s30.BridgeMergeNestedValidation(report, s45.BridgeUEAssociatedLogicalS1ConnectionItemResAckIEValueValidateS1APIEContainer(s45.UEAssociatedLogicalS1ConnectionItemResAckIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s45.UEAssociatedLogicalS1ConnectionItemResAckIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
func BridgeWalkValidationUECapabilityInfoIndication(v *s45.UECapabilityInfoIndication, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s14.UECapabilityInfoIndicationIEs().MMEUES1APID().Info(), s14.UECapabilityInfoIndicationIEs().ENBUES1APID().Info(), s14.UECapabilityInfoIndicationIEs().UERadioCapability().Info(), s14.UECapabilityInfoIndicationIEs().UERadioCapabilityForPaging().Info(), s14.UECapabilityInfoIndicationIEs().UEApplicationLayerMeasurementCapability().Info(), s14.UECapabilityInfoIndicationIEs().LTEMIndication().Info(), s14.UECapabilityInfoIndicationIEs().UERadioCapabilityNRFormat().Info(), s14.UECapabilityInfoIndicationIEs().UERadioCapabilityForPagingNRFormat().Info()}
			s30.BridgeMergeNestedValidation(report, s45.BridgeUECapabilityInfoIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextModificationConfirm(v *s45.UEContextModificationConfirm, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s27.UEContextModificationConfirmIEs().MMEUES1APID().Info(), s27.UEContextModificationConfirmIEs().ENBUES1APID().Info(), s27.UEContextModificationConfirmIEs().CSGMembershipStatus().Info(), s27.UEContextModificationConfirmIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s45.BridgeUEContextModificationConfirmIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextModificationFailure(v *s45.UEContextModificationFailure, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s27.UEContextModificationFailureIEs().MMEUES1APID().Info(), s27.UEContextModificationFailureIEs().ENBUES1APID().Info(), s27.UEContextModificationFailureIEs().Cause().Info(), s27.UEContextModificationFailureIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s46.BridgeUEContextModificationFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s61.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextModificationIndication(v *s46.UEContextModificationIndication, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s24.UEContextModificationIndicationIEs().MMEUES1APID().Info(), s24.UEContextModificationIndicationIEs().ENBUES1APID().Info(), s24.UEContextModificationIndicationIEs().CSGMembershipInfo().Info()}
			s30.BridgeMergeNestedValidation(report, s46.BridgeUEContextModificationIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(226):
				if value, ok := fields[i].Value.AsCSGMembershipInfo(); ok {
					s61.BridgeWalkValidationCSGMembershipInfo(value, report, fmt.Sprintf("%s[%d]{id=226}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextModificationResponse(v *s46.UEContextModificationResponse, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s27.UEContextModificationResponseIEs().MMEUES1APID().Info(), s27.UEContextModificationResponseIEs().ENBUES1APID().Info(), s27.UEContextModificationResponseIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s46.BridgeUEContextModificationResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextReleaseCommand(v *s47.UEContextReleaseCommand, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s46.UEContextReleaseCommandIEs().UES1APIDs().Info(), s46.UEContextReleaseCommandIEs().Cause().Info()}
			s30.BridgeMergeNestedValidation(report, s47.BridgeUEContextReleaseCommandIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(99):
				if value, ok := fields[i].Value.AsUES1APIDs(); ok {
					BridgeWalkValidationUES1APIDs(value, report, fmt.Sprintf("%s[%d]{id=99}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s61.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextReleaseComplete(v *s57.UEContextReleaseComplete, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s57.UEContextReleaseCompleteIEs().MMEUES1APID().Info(), s57.UEContextReleaseCompleteIEs().ENBUES1APID().Info(), s57.UEContextReleaseCompleteIEs().CriticalityDiagnostics().Info(), s57.UEContextReleaseCompleteIEs().UserLocationInformation().Info(), s57.UEContextReleaseCompleteIEs().InformationOnRecommendedCellsAndENBsForPaging().Info(), s57.UEContextReleaseCompleteIEs().CellIdentifierAndCELevelForCECapableUEs().Info(), s57.UEContextReleaseCompleteIEs().SecondaryRATDataUsageReportList().Info(), s57.UEContextReleaseCompleteIEs().TimeSinceSecondaryNodeRelease().Info()}
			s30.BridgeMergeNestedValidation(report, s57.BridgeUEContextReleaseCompleteIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(213):
				if value, ok := fields[i].Value.AsInformationOnRecommendedCellsAndENBsForPaging(); ok {
					s62.BridgeWalkValidationInformationOnRecommendedCellsAndENBsForPaging(value, report, fmt.Sprintf("%s[%d]{id=213}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(212):
				if value, ok := fields[i].Value.AsCellIdentifierAndCELevelForCECapableUEs(); ok {
					s61.BridgeWalkValidationCellIdentifierAndCELevelForCECapableUEs(value, report, fmt.Sprintf("%s[%d]{id=212}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s62.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextReleaseRequest(v *s53.UEContextReleaseRequest, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s53.UEContextReleaseRequestIEs().MMEUES1APID().Info(), s53.UEContextReleaseRequestIEs().ENBUES1APID().Info(), s53.UEContextReleaseRequestIEs().Cause().Info(), s53.UEContextReleaseRequestIEs().GWContextReleaseIndication().Info(), s53.UEContextReleaseRequestIEs().SecondaryRATDataUsageReportList().Info()}
			s30.BridgeMergeNestedValidation(report, s53.BridgeUEContextReleaseRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s61.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s62.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextResumeFailure(v *s46.UEContextResumeFailure, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s28.UEContextResumeFailureIEs().MMEUES1APID().Info(), s28.UEContextResumeFailureIEs().ENBUES1APID().Info(), s28.UEContextResumeFailureIEs().Cause().Info(), s28.UEContextResumeFailureIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s46.BridgeUEContextResumeFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					s61.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextResumeRequest(v *s48.UEContextResumeRequest, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s48.UEContextResumeRequestIEs().MMEUES1APID().Info(), s48.UEContextResumeRequestIEs().ENBUES1APID().Info(), s48.UEContextResumeRequestIEs().ERABFailedToResumeListResumeReq().Info(), s48.UEContextResumeRequestIEs().RRCResumeCause().Info()}
			s30.BridgeMergeNestedValidation(report, s48.BridgeUEContextResumeRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(235):
				if value, ok := fields[i].Value.AsERABFailedToResumeListResumeReq(); ok {
					s61.BridgeWalkValidationERABFailedToResumeListResumeReq(value, report, fmt.Sprintf("%s[%d]{id=235}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextResumeResponse(v *s49.UEContextResumeResponse, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s49.UEContextResumeResponseIEs().MMEUES1APID().Info(), s49.UEContextResumeResponseIEs().ENBUES1APID().Info(), s49.UEContextResumeResponseIEs().ERABFailedToResumeListResumeRes().Info(), s49.UEContextResumeResponseIEs().CriticalityDiagnostics().Info(), s49.UEContextResumeResponseIEs().SecurityContext().Info(), s49.UEContextResumeResponseIEs().PendingDataIndication().Info()}
			s30.BridgeMergeNestedValidation(report, s49.BridgeUEContextResumeResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(237):
				if value, ok := fields[i].Value.AsERABFailedToResumeListResumeRes(); ok {
					s61.BridgeWalkValidationERABFailedToResumeListResumeRes(value, report, fmt.Sprintf("%s[%d]{id=237}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(40):
				if value, ok := fields[i].Value.AsSecurityContext(); ok {
					s62.BridgeWalkValidationSecurityContext(value, report, fmt.Sprintf("%s[%d]{id=40}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextSuspendRequest(v *s57.UEContextSuspendRequest, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s57.UEContextSuspendRequestIEs().MMEUES1APID().Info(), s57.UEContextSuspendRequestIEs().ENBUES1APID().Info(), s57.UEContextSuspendRequestIEs().InformationOnRecommendedCellsAndENBsForPaging().Info(), s57.UEContextSuspendRequestIEs().CellIdentifierAndCELevelForCECapableUEs().Info(), s57.UEContextSuspendRequestIEs().SecondaryRATDataUsageReportList().Info(), s57.UEContextSuspendRequestIEs().UserLocationInformation().Info(), s57.UEContextSuspendRequestIEs().TimeSinceSecondaryNodeRelease().Info()}
			s30.BridgeMergeNestedValidation(report, s57.BridgeUEContextSuspendRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(213):
				if value, ok := fields[i].Value.AsInformationOnRecommendedCellsAndENBsForPaging(); ok {
					s62.BridgeWalkValidationInformationOnRecommendedCellsAndENBsForPaging(value, report, fmt.Sprintf("%s[%d]{id=213}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(212):
				if value, ok := fields[i].Value.AsCellIdentifierAndCELevelForCECapableUEs(); ok {
					s61.BridgeWalkValidationCellIdentifierAndCELevelForCECapableUEs(value, report, fmt.Sprintf("%s[%d]{id=212}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(264):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportList(); ok {
					s62.BridgeWalkValidationSecondaryRATDataUsageReportList(value, report, fmt.Sprintf("%s[%d]{id=264}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(189):
				if value, ok := fields[i].Value.AsUserLocationInformation(); ok {
					BridgeWalkValidationUserLocationInformation(value, report, fmt.Sprintf("%s[%d]{id=189}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextSuspendResponse(v *s46.UEContextSuspendResponse, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s37.UEContextSuspendResponseIEs().MMEUES1APID().Info(), s37.UEContextSuspendResponseIEs().ENBUES1APID().Info(), s37.UEContextSuspendResponseIEs().CriticalityDiagnostics().Info(), s37.UEContextSuspendResponseIEs().SecurityContext().Info()}
			s30.BridgeMergeNestedValidation(report, s46.BridgeUEContextSuspendResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(40):
				if value, ok := fields[i].Value.AsSecurityContext(); ok {
					s62.BridgeWalkValidationSecurityContext(value, report, fmt.Sprintf("%s[%d]{id=40}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEHistoryInformation(v *s52.UEHistoryInformation, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s25.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		s62.BridgeWalkValidationLastVisitedCellItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationUEInformationTransfer(v *s46.UEInformationTransfer, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s40.UEInformationTransferIEs().STMSI().Info(), s40.UEInformationTransferIEs().UELevelQoSParameters().Info(), s40.UEInformationTransferIEs().UERadioCapability().Info(), s40.UEInformationTransferIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s40.UEInformationTransferIEs().PendingDataIndication().Info(), s40.UEInformationTransferIEs().MaskedIMEISV().Info()}
			s30.BridgeMergeNestedValidation(report, s46.BridgeUEInformationTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(96):
				if value, ok := fields[i].Value.AsSTMSI(); ok {
					s62.BridgeWalkValidationSTMSI(value, report, fmt.Sprintf("%s[%d]{id=96}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(252):
				if value, ok := fields[i].Value.AsUELevelQoSParameters(); ok {
					s61.BridgeWalkValidationERABLevelQoSParameters(value, report, fmt.Sprintf("%s[%d]{id=252}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					s62.BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEPagingID(v *s36.UEPagingID, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.UEPagingIDChoiceSTMSI && v.STMSI != nil {
		s62.BridgeWalkValidationSTMSI(v.STMSI, report, path+".s-TMSI", false)
	}
}
func BridgeWalkValidationUERadioCapabilityIDMappingRequest(v *s46.UERadioCapabilityIDMappingRequest, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s14.UERadioCapabilityIDMappingRequestIEs().UERadioCapabilityID().Info()}
			s30.BridgeMergeNestedValidation(report, s46.BridgeUERadioCapabilityIDMappingRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUERadioCapabilityIDMappingResponse(v *s46.UERadioCapabilityIDMappingResponse, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s28.UERadioCapabilityIDMappingResponseIEs().UERadioCapabilityID().Info(), s28.UERadioCapabilityIDMappingResponseIEs().UERadioCapability().Info(), s28.UERadioCapabilityIDMappingResponseIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s46.BridgeUERadioCapabilityIDMappingResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUERadioCapabilityMatchRequest(v *s46.UERadioCapabilityMatchRequest, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s14.UERadioCapabilityMatchRequestIEs().MMEUES1APID().Info(), s14.UERadioCapabilityMatchRequestIEs().ENBUES1APID().Info(), s14.UERadioCapabilityMatchRequestIEs().UERadioCapability().Info(), s14.UERadioCapabilityMatchRequestIEs().UERadioCapabilityID().Info()}
			s30.BridgeMergeNestedValidation(report, s46.BridgeUERadioCapabilityMatchRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUERadioCapabilityMatchResponse(v *s46.UERadioCapabilityMatchResponse, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s28.UERadioCapabilityMatchResponseIEs().MMEUES1APID().Info(), s28.UERadioCapabilityMatchResponseIEs().ENBUES1APID().Info(), s28.UERadioCapabilityMatchResponseIEs().VoiceSupportMatchIndicator().Info(), s28.UERadioCapabilityMatchResponseIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s46.BridgeUERadioCapabilityMatchResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUES1APIDPair(v *s46.UES1APIDPair, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s47.BridgeUES1APIDPairExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUES1APIDs(v *s46.UES1APIDs, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.UES1APIDsChoiceUES1APIDPair && v.UES1APIDPair != nil {
		BridgeWalkValidationUES1APIDPair(v.UES1APIDPair, report, path+".uE-S1AP-ID-pair", false)
	}
}
func BridgeWalkValidationUESecurityCapabilities(v *s47.UESecurityCapabilities, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s47.BridgeUESecurityCapabilitiesExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUESidelinkAggregateMaximumBitrate(v *s47.UESidelinkAggregateMaximumBitrate, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s47.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationULCPSecurityInformation(v *s47.ULCPSecurityInformation, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s47.BridgeULCPSecurityInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUnsuccessfulOutcome(v *s46.UnsuccessfulOutcome, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUplinkNASTransport(v *s55.UplinkNASTransport, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s41.UplinkNASTransportIEs().MMEUES1APID().Info(), s41.UplinkNASTransportIEs().ENBUES1APID().Info(), s41.UplinkNASTransportIEs().NASPDU().Info(), s41.UplinkNASTransportIEs().EUTRANCGI().Info(), s41.UplinkNASTransportIEs().TAI().Info(), s41.UplinkNASTransportIEs().GWTransportLayerAddress().Info(), s41.UplinkNASTransportIEs().SIPTOLGWTransportLayerAddress().Info(), s41.UplinkNASTransportIEs().LHNID().Info(), s41.UplinkNASTransportIEs().PSCellInformation().Info(), s41.UplinkNASTransportIEs().LTENTNTAIInformation().Info()}
			s30.BridgeMergeNestedValidation(report, s55.BridgeUplinkNASTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					s61.BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(67):
				if value, ok := fields[i].Value.AsTAI(); ok {
					s62.BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(288):
				if value, ok := fields[i].Value.AsPSCellInformation(); ok {
					s62.BridgeWalkValidationPSCellInformation(value, report, fmt.Sprintf("%s[%d]{id=288}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					s62.BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUplinkNonUEAssociatedLPPaTransport(v *s55.UplinkNonUEAssociatedLPPaTransport, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s14.UplinkNonUEAssociatedLPPaTransportIEs().RoutingID().Info(), s14.UplinkNonUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
			s30.BridgeMergeNestedValidation(report, s55.BridgeUplinkNonUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUplinkS1cdma2000tunnelling(v *s55.UplinkS1cdma2000tunnelling, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s25.UplinkS1cdma2000tunnellingIEs().MMEUES1APID().Info(), s25.UplinkS1cdma2000tunnellingIEs().ENBUES1APID().Info(), s25.UplinkS1cdma2000tunnellingIEs().Cdma2000RATType().Info(), s25.UplinkS1cdma2000tunnellingIEs().Cdma2000SectorID().Info(), s25.UplinkS1cdma2000tunnellingIEs().Cdma2000HORequiredIndication().Info(), s25.UplinkS1cdma2000tunnellingIEs().Cdma2000OneXSRVCCInfo().Info(), s25.UplinkS1cdma2000tunnellingIEs().Cdma2000OneXRAND().Info(), s25.UplinkS1cdma2000tunnellingIEs().Cdma2000PDU().Info(), s25.UplinkS1cdma2000tunnellingIEs().EUTRANRoundTripDelayEstimationInfo().Info()}
			s30.BridgeMergeNestedValidation(report, s55.BridgeUplinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(102):
				if value, ok := fields[i].Value.AsCdma2000OneXSRVCCInfo(); ok {
					s61.BridgeWalkValidationCdma2000OneXSRVCCInfo(value, report, fmt.Sprintf("%s[%d]{id=102}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUplinkUEAssociatedLPPaTransport(v *s55.UplinkUEAssociatedLPPaTransport, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s14.UplinkUEAssociatedLPPaTransportIEs().MMEUES1APID().Info(), s14.UplinkUEAssociatedLPPaTransportIEs().ENBUES1APID().Info(), s14.UplinkUEAssociatedLPPaTransportIEs().RoutingID().Info(), s14.UplinkUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
			s30.BridgeMergeNestedValidation(report, s55.BridgeUplinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUserLocationInformation(v *s55.UserLocationInformation, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s61.BridgeWalkValidationEUTRANCGI(&v.EutranCgi, report, path+".eutran-cgi", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s62.BridgeWalkValidationTAI(&v.Tai, report, path+".tai", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s25.UserLocationInformationExtIEs().PSCellInformation().Info()), s00.FieldInfo(s25.UserLocationInformationExtIEs().LTENTNTAIInformation().Info())}
				s30.BridgeMergeNestedValidation(report, s57.BridgeUserLocationInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(288):
					if value, ok := fields[i].ExtensionValue.AsPSCellInformation(); ok {
						s62.BridgeWalkValidationPSCellInformation(value, report, fmt.Sprintf("%s[%d]{id=288}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(339):
					if value, ok := fields[i].ExtensionValue.AsLTENTNTAIInformation(); ok {
						s62.BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationV2XServicesAuthorized(v *s57.V2XServicesAuthorized, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s58.BridgeV2XServicesAuthorizedExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
