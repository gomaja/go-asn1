// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s62 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s62

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s22 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s22"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
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
	s47 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s47"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s51 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s51"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	s53 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s53"
	s54 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s54"
	s58 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s58"
	s61 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s61"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func NewPathSwitchRequestFailure(fields s27.PathSwitchRequestFailureIEContainer, options ...aper.BuildOption) (s30.PathSwitchRequestFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s30.PathSwitchRequestFailure{}, aper.OperationError(err, "PathSwitchRequestFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s27.PathSwitchRequestFailureIEField](bb, uint64(len(fields))); err != nil {
		return s30.PathSwitchRequestFailure{}, aper.OperationError(err, "PathSwitchRequestFailure")
	}
	v := s30.PathSwitchRequestFailure{ProtocolIEs: make(s27.PathSwitchRequestFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidatePathSwitchRequestFailureBudget(&v, budget)
	if err != nil {
		return s30.PathSwitchRequestFailure{}, aper.OperationError(err, "PathSwitchRequestFailure")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s30.PathSwitchRequestFailure{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "PathSwitchRequestFailure")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s30.PathSwitchRequestFailure{}, aper.OperationError(&s25.BuildError{Issues: issues}, "PathSwitchRequestFailure")
	}
	if _, err := s30.BridgePathSwitchRequestFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s30.PathSwitchRequestFailure{}, aper.OperationError(fmt.Errorf("%s %w", "PathSwitchRequestFailure.protocolIEs:", err), "PathSwitchRequestFailure")
	}
	return v, aper.OperationError(nil, "PathSwitchRequestFailure")
}
func NewInitialContextSetupResponse(fields s50.InitialContextSetupResponseIEContainer, options ...aper.BuildOption) (s50.InitialContextSetupResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s50.InitialContextSetupResponse{}, aper.OperationError(err, "InitialContextSetupResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s50.InitialContextSetupResponseIEField](bb, uint64(len(fields))); err != nil {
		return s50.InitialContextSetupResponse{}, aper.OperationError(err, "InitialContextSetupResponse")
	}
	v := s50.InitialContextSetupResponse{ProtocolIEs: make(s50.InitialContextSetupResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateInitialContextSetupResponseBudget(&v, budget)
	if err != nil {
		return s50.InitialContextSetupResponse{}, aper.OperationError(err, "InitialContextSetupResponse")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s50.InitialContextSetupResponse{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "InitialContextSetupResponse")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s50.InitialContextSetupResponse{}, aper.OperationError(&s25.BuildError{Issues: issues}, "InitialContextSetupResponse")
	}
	if _, err := s50.BridgeInitialContextSetupResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s50.InitialContextSetupResponse{}, aper.OperationError(fmt.Errorf("%s %w", "InitialContextSetupResponse.protocolIEs:", err), "InitialContextSetupResponse")
	}
	return v, aper.OperationError(nil, "InitialContextSetupResponse")
}
func NewInitialContextSetupFailure(fields s26.InitialContextSetupFailureIEContainer, options ...aper.BuildOption) (s30.InitialContextSetupFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s30.InitialContextSetupFailure{}, aper.OperationError(err, "InitialContextSetupFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s26.InitialContextSetupFailureIEField](bb, uint64(len(fields))); err != nil {
		return s30.InitialContextSetupFailure{}, aper.OperationError(err, "InitialContextSetupFailure")
	}
	v := s30.InitialContextSetupFailure{ProtocolIEs: make(s26.InitialContextSetupFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateInitialContextSetupFailureBudget(&v, budget)
	if err != nil {
		return s30.InitialContextSetupFailure{}, aper.OperationError(err, "InitialContextSetupFailure")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s30.InitialContextSetupFailure{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "InitialContextSetupFailure")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s30.InitialContextSetupFailure{}, aper.OperationError(&s25.BuildError{Issues: issues}, "InitialContextSetupFailure")
	}
	if _, err := s30.BridgeInitialContextSetupFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s30.InitialContextSetupFailure{}, aper.OperationError(fmt.Errorf("%s %w", "InitialContextSetupFailure.protocolIEs:", err), "InitialContextSetupFailure")
	}
	return v, aper.OperationError(nil, "InitialContextSetupFailure")
}
func NewDownlinkNASTransport(fields s53.DownlinkNASTransportIEContainer, options ...aper.BuildOption) (s53.DownlinkNASTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s53.DownlinkNASTransport{}, aper.OperationError(err, "DownlinkNASTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s53.DownlinkNASTransportIEField](bb, uint64(len(fields))); err != nil {
		return s53.DownlinkNASTransport{}, aper.OperationError(err, "DownlinkNASTransport")
	}
	v := s53.DownlinkNASTransport{ProtocolIEs: make(s53.DownlinkNASTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateDownlinkNASTransportBudget(&v, budget)
	if err != nil {
		return s53.DownlinkNASTransport{}, aper.OperationError(err, "DownlinkNASTransport")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s53.DownlinkNASTransport{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "DownlinkNASTransport")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s53.DownlinkNASTransport{}, aper.OperationError(&s25.BuildError{Issues: issues}, "DownlinkNASTransport")
	}
	if _, err := s53.BridgeDownlinkNASTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s53.DownlinkNASTransport{}, aper.OperationError(fmt.Errorf("%s %w", "DownlinkNASTransport.protocolIEs:", err), "DownlinkNASTransport")
	}
	return v, aper.OperationError(nil, "DownlinkNASTransport")
}
func NewErrorIndication(fields s36.ErrorIndicationIEContainer, options ...aper.BuildOption) (s36.ErrorIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.ErrorIndication{}, aper.OperationError(err, "ErrorIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s36.ErrorIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s36.ErrorIndication{}, aper.OperationError(err, "ErrorIndication")
	}
	v := s36.ErrorIndication{ProtocolIEs: make(s36.ErrorIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateErrorIndicationBudget(&v, budget)
	if err != nil {
		return s36.ErrorIndication{}, aper.OperationError(err, "ErrorIndication")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s36.ErrorIndication{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ErrorIndication")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.ErrorIndication{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ErrorIndication")
	}
	if _, err := s36.BridgeErrorIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.ErrorIndication{}, aper.OperationError(fmt.Errorf("%s %w", "ErrorIndication.protocolIEs:", err), "ErrorIndication")
	}
	return v, aper.OperationError(nil, "ErrorIndication")
}
func NewNASNonDeliveryIndication(fields s22.NASNonDeliveryIndicationIEContainer, options ...aper.BuildOption) (s30.NASNonDeliveryIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s30.NASNonDeliveryIndication{}, aper.OperationError(err, "NASNonDeliveryIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s22.NASNonDeliveryIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s30.NASNonDeliveryIndication{}, aper.OperationError(err, "NASNonDeliveryIndication")
	}
	v := s30.NASNonDeliveryIndication{ProtocolIEs: make(s22.NASNonDeliveryIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateNASNonDeliveryIndicationBudget(&v, budget)
	if err != nil {
		return s30.NASNonDeliveryIndication{}, aper.OperationError(err, "NASNonDeliveryIndication")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s30.NASNonDeliveryIndication{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "NASNonDeliveryIndication")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s30.NASNonDeliveryIndication{}, aper.OperationError(&s25.BuildError{Issues: issues}, "NASNonDeliveryIndication")
	}
	if _, err := s30.BridgeNASNonDeliveryIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s30.NASNonDeliveryIndication{}, aper.OperationError(fmt.Errorf("%s %w", "NASNonDeliveryIndication.protocolIEs:", err), "NASNonDeliveryIndication")
	}
	return v, aper.OperationError(nil, "NASNonDeliveryIndication")
}
func NewS1SetupRequest(fields s54.S1SetupRequestIEContainer, options ...aper.BuildOption) (s54.S1SetupRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s54.S1SetupRequest{}, aper.OperationError(err, "S1SetupRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s54.S1SetupRequestIEField](bb, uint64(len(fields))); err != nil {
		return s54.S1SetupRequest{}, aper.OperationError(err, "S1SetupRequest")
	}
	v := s54.S1SetupRequest{ProtocolIEs: make(s54.S1SetupRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateS1SetupRequestBudget(&v, budget)
	if err != nil {
		return s54.S1SetupRequest{}, aper.OperationError(err, "S1SetupRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s54.S1SetupRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "S1SetupRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s54.S1SetupRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "S1SetupRequest")
	}
	if _, err := s54.BridgeS1SetupRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s54.S1SetupRequest{}, aper.OperationError(fmt.Errorf("%s %w", "S1SetupRequest.protocolIEs:", err), "S1SetupRequest")
	}
	return v, aper.OperationError(nil, "S1SetupRequest")
}
func NewS1SetupResponse(fields s54.S1SetupResponseIEContainer, options ...aper.BuildOption) (s54.S1SetupResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s54.S1SetupResponse{}, aper.OperationError(err, "S1SetupResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s54.S1SetupResponseIEField](bb, uint64(len(fields))); err != nil {
		return s54.S1SetupResponse{}, aper.OperationError(err, "S1SetupResponse")
	}
	v := s54.S1SetupResponse{ProtocolIEs: make(s54.S1SetupResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateS1SetupResponseBudget(&v, budget)
	if err != nil {
		return s54.S1SetupResponse{}, aper.OperationError(err, "S1SetupResponse")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s54.S1SetupResponse{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "S1SetupResponse")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s54.S1SetupResponse{}, aper.OperationError(&s25.BuildError{Issues: issues}, "S1SetupResponse")
	}
	if _, err := s54.BridgeS1SetupResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s54.S1SetupResponse{}, aper.OperationError(fmt.Errorf("%s %w", "S1SetupResponse.protocolIEs:", err), "S1SetupResponse")
	}
	return v, aper.OperationError(nil, "S1SetupResponse")
}
func NewS1SetupFailure(fields s27.S1SetupFailureIEContainer, options ...aper.BuildOption) (s31.S1SetupFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s31.S1SetupFailure{}, aper.OperationError(err, "S1SetupFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s27.S1SetupFailureIEField](bb, uint64(len(fields))); err != nil {
		return s31.S1SetupFailure{}, aper.OperationError(err, "S1SetupFailure")
	}
	v := s31.S1SetupFailure{ProtocolIEs: make(s27.S1SetupFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateS1SetupFailureBudget(&v, budget)
	if err != nil {
		return s31.S1SetupFailure{}, aper.OperationError(err, "S1SetupFailure")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s31.S1SetupFailure{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "S1SetupFailure")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s31.S1SetupFailure{}, aper.OperationError(&s25.BuildError{Issues: issues}, "S1SetupFailure")
	}
	if _, err := s31.BridgeS1SetupFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s31.S1SetupFailure{}, aper.OperationError(fmt.Errorf("%s %w", "S1SetupFailure.protocolIEs:", err), "S1SetupFailure")
	}
	return v, aper.OperationError(nil, "S1SetupFailure")
}
func NewMMEStatusTransfer(fields s25.MMEStatusTransferIEContainer, options ...aper.BuildOption) (s30.MMEStatusTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s30.MMEStatusTransfer{}, aper.OperationError(err, "MMEStatusTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s25.MMEStatusTransferIEField](bb, uint64(len(fields))); err != nil {
		return s30.MMEStatusTransfer{}, aper.OperationError(err, "MMEStatusTransfer")
	}
	v := s30.MMEStatusTransfer{ProtocolIEs: make(s25.MMEStatusTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEStatusTransferBudget(&v, budget)
	if err != nil {
		return s30.MMEStatusTransfer{}, aper.OperationError(err, "MMEStatusTransfer")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s30.MMEStatusTransfer{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "MMEStatusTransfer")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s30.MMEStatusTransfer{}, aper.OperationError(&s25.BuildError{Issues: issues}, "MMEStatusTransfer")
	}
	if _, err := s30.BridgeMMEStatusTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s30.MMEStatusTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "MMEStatusTransfer.protocolIEs:", err), "MMEStatusTransfer")
	}
	return v, aper.OperationError(nil, "MMEStatusTransfer")
}
func NewENBConfigurationUpdate(fields s54.ENBConfigurationUpdateIEContainer, options ...aper.BuildOption) (s54.ENBConfigurationUpdate, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s54.ENBConfigurationUpdate{}, aper.OperationError(err, "ENBConfigurationUpdate")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s54.ENBConfigurationUpdateIEField](bb, uint64(len(fields))); err != nil {
		return s54.ENBConfigurationUpdate{}, aper.OperationError(err, "ENBConfigurationUpdate")
	}
	v := s54.ENBConfigurationUpdate{ProtocolIEs: make(s54.ENBConfigurationUpdateIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBConfigurationUpdateBudget(&v, budget)
	if err != nil {
		return s54.ENBConfigurationUpdate{}, aper.OperationError(err, "ENBConfigurationUpdate")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s54.ENBConfigurationUpdate{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ENBConfigurationUpdate")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s54.ENBConfigurationUpdate{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ENBConfigurationUpdate")
	}
	if _, err := s54.BridgeENBConfigurationUpdateMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s54.ENBConfigurationUpdate{}, aper.OperationError(fmt.Errorf("%s %w", "ENBConfigurationUpdate.protocolIEs:", err), "ENBConfigurationUpdate")
	}
	return v, aper.OperationError(nil, "ENBConfigurationUpdate")
}
func NewMMEConfigurationUpdate(fields s54.MMEConfigurationUpdateIEContainer, options ...aper.BuildOption) (s54.MMEConfigurationUpdate, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s54.MMEConfigurationUpdate{}, aper.OperationError(err, "MMEConfigurationUpdate")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s54.MMEConfigurationUpdateIEField](bb, uint64(len(fields))); err != nil {
		return s54.MMEConfigurationUpdate{}, aper.OperationError(err, "MMEConfigurationUpdate")
	}
	v := s54.MMEConfigurationUpdate{ProtocolIEs: make(s54.MMEConfigurationUpdateIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEConfigurationUpdateBudget(&v, budget)
	if err != nil {
		return s54.MMEConfigurationUpdate{}, aper.OperationError(err, "MMEConfigurationUpdate")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s54.MMEConfigurationUpdate{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "MMEConfigurationUpdate")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s54.MMEConfigurationUpdate{}, aper.OperationError(&s25.BuildError{Issues: issues}, "MMEConfigurationUpdate")
	}
	if _, err := s54.BridgeMMEConfigurationUpdateMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s54.MMEConfigurationUpdate{}, aper.OperationError(fmt.Errorf("%s %w", "MMEConfigurationUpdate.protocolIEs:", err), "MMEConfigurationUpdate")
	}
	return v, aper.OperationError(nil, "MMEConfigurationUpdate")
}
func NewMMEConfigurationUpdateAcknowledge(fields s26.MMEConfigurationUpdateAcknowledgeIEContainer, options ...aper.BuildOption) (s30.MMEConfigurationUpdateAcknowledge, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s30.MMEConfigurationUpdateAcknowledge{}, aper.OperationError(err, "MMEConfigurationUpdateAcknowledge")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s26.MMEConfigurationUpdateAcknowledgeIEField](bb, uint64(len(fields))); err != nil {
		return s30.MMEConfigurationUpdateAcknowledge{}, aper.OperationError(err, "MMEConfigurationUpdateAcknowledge")
	}
	v := s30.MMEConfigurationUpdateAcknowledge{ProtocolIEs: make(s26.MMEConfigurationUpdateAcknowledgeIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEConfigurationUpdateAcknowledgeBudget(&v, budget)
	if err != nil {
		return s30.MMEConfigurationUpdateAcknowledge{}, aper.OperationError(err, "MMEConfigurationUpdateAcknowledge")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s30.MMEConfigurationUpdateAcknowledge{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "MMEConfigurationUpdateAcknowledge")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s30.MMEConfigurationUpdateAcknowledge{}, aper.OperationError(&s25.BuildError{Issues: issues}, "MMEConfigurationUpdateAcknowledge")
	}
	if _, err := s30.BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s30.MMEConfigurationUpdateAcknowledge{}, aper.OperationError(fmt.Errorf("%s %w", "MMEConfigurationUpdateAcknowledge.protocolIEs:", err), "MMEConfigurationUpdateAcknowledge")
	}
	return v, aper.OperationError(nil, "MMEConfigurationUpdateAcknowledge")
}
func NewMMEConfigurationUpdateFailure(fields s27.MMEConfigurationUpdateFailureIEContainer, options ...aper.BuildOption) (s30.MMEConfigurationUpdateFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s30.MMEConfigurationUpdateFailure{}, aper.OperationError(err, "MMEConfigurationUpdateFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s26.MMEConfigurationUpdateFailureIEField](bb, uint64(len(fields))); err != nil {
		return s30.MMEConfigurationUpdateFailure{}, aper.OperationError(err, "MMEConfigurationUpdateFailure")
	}
	v := s30.MMEConfigurationUpdateFailure{ProtocolIEs: make(s27.MMEConfigurationUpdateFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEConfigurationUpdateFailureBudget(&v, budget)
	if err != nil {
		return s30.MMEConfigurationUpdateFailure{}, aper.OperationError(err, "MMEConfigurationUpdateFailure")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s30.MMEConfigurationUpdateFailure{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "MMEConfigurationUpdateFailure")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s30.MMEConfigurationUpdateFailure{}, aper.OperationError(&s25.BuildError{Issues: issues}, "MMEConfigurationUpdateFailure")
	}
	if _, err := s30.BridgeMMEConfigurationUpdateFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s30.MMEConfigurationUpdateFailure{}, aper.OperationError(fmt.Errorf("%s %w", "MMEConfigurationUpdateFailure.protocolIEs:", err), "MMEConfigurationUpdateFailure")
	}
	return v, aper.OperationError(nil, "MMEConfigurationUpdateFailure")
}
func NewLocationReportingControl(fields s31.LocationReportingControlIEContainer, options ...aper.BuildOption) (s31.LocationReportingControl, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s31.LocationReportingControl{}, aper.OperationError(err, "LocationReportingControl")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s31.LocationReportingControlIEField](bb, uint64(len(fields))); err != nil {
		return s31.LocationReportingControl{}, aper.OperationError(err, "LocationReportingControl")
	}
	v := s31.LocationReportingControl{ProtocolIEs: make(s31.LocationReportingControlIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateLocationReportingControlBudget(&v, budget)
	if err != nil {
		return s31.LocationReportingControl{}, aper.OperationError(err, "LocationReportingControl")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s31.LocationReportingControl{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "LocationReportingControl")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s31.LocationReportingControl{}, aper.OperationError(&s25.BuildError{Issues: issues}, "LocationReportingControl")
	}
	if _, err := s31.BridgeLocationReportingControlMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s31.LocationReportingControl{}, aper.OperationError(fmt.Errorf("%s %w", "LocationReportingControl.protocolIEs:", err), "LocationReportingControl")
	}
	return v, aper.OperationError(nil, "LocationReportingControl")
}
func NewLocationReportingFailureIndication(fields s22.LocationReportingFailureIndicationIEContainer, options ...aper.BuildOption) (s30.LocationReportingFailureIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s30.LocationReportingFailureIndication{}, aper.OperationError(err, "LocationReportingFailureIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s22.LocationReportingFailureIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s30.LocationReportingFailureIndication{}, aper.OperationError(err, "LocationReportingFailureIndication")
	}
	v := s30.LocationReportingFailureIndication{ProtocolIEs: make(s22.LocationReportingFailureIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateLocationReportingFailureIndicationBudget(&v, budget)
	if err != nil {
		return s30.LocationReportingFailureIndication{}, aper.OperationError(err, "LocationReportingFailureIndication")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s30.LocationReportingFailureIndication{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "LocationReportingFailureIndication")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s30.LocationReportingFailureIndication{}, aper.OperationError(&s25.BuildError{Issues: issues}, "LocationReportingFailureIndication")
	}
	if _, err := s30.BridgeLocationReportingFailureIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s30.LocationReportingFailureIndication{}, aper.OperationError(fmt.Errorf("%s %w", "LocationReportingFailureIndication.protocolIEs:", err), "LocationReportingFailureIndication")
	}
	return v, aper.OperationError(nil, "LocationReportingFailureIndication")
}
func NewLocationReport(fields s40.LocationReportIEContainer, options ...aper.BuildOption) (s42.LocationReport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s42.LocationReport{}, aper.OperationError(err, "LocationReport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s40.LocationReportIEField](bb, uint64(len(fields))); err != nil {
		return s42.LocationReport{}, aper.OperationError(err, "LocationReport")
	}
	v := s42.LocationReport{ProtocolIEs: make(s40.LocationReportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateLocationReportBudget(&v, budget)
	if err != nil {
		return s42.LocationReport{}, aper.OperationError(err, "LocationReport")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s42.LocationReport{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "LocationReport")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s42.LocationReport{}, aper.OperationError(&s25.BuildError{Issues: issues}, "LocationReport")
	}
	if _, err := s42.BridgeLocationReportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s42.LocationReport{}, aper.OperationError(fmt.Errorf("%s %w", "LocationReport.protocolIEs:", err), "LocationReport")
	}
	return v, aper.OperationError(nil, "LocationReport")
}
func NewOverloadStart(fields s51.OverloadStartIEContainer, options ...aper.BuildOption) (s52.OverloadStart, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.OverloadStart{}, aper.OperationError(err, "OverloadStart")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s51.OverloadStartIEField](bb, uint64(len(fields))); err != nil {
		return s52.OverloadStart{}, aper.OperationError(err, "OverloadStart")
	}
	v := s52.OverloadStart{ProtocolIEs: make(s51.OverloadStartIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateOverloadStartBudget(&v, budget)
	if err != nil {
		return s52.OverloadStart{}, aper.OperationError(err, "OverloadStart")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s52.OverloadStart{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "OverloadStart")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.OverloadStart{}, aper.OperationError(&s25.BuildError{Issues: issues}, "OverloadStart")
	}
	if _, err := s52.BridgeOverloadStartMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s52.OverloadStart{}, aper.OperationError(fmt.Errorf("%s %w", "OverloadStart.protocolIEs:", err), "OverloadStart")
	}
	return v, aper.OperationError(nil, "OverloadStart")
}
func NewOverloadStop(fields s52.OverloadStopIEContainer, options ...aper.BuildOption) (s52.OverloadStop, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.OverloadStop{}, aper.OperationError(err, "OverloadStop")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s52.OverloadStopIEField](bb, uint64(len(fields))); err != nil {
		return s52.OverloadStop{}, aper.OperationError(err, "OverloadStop")
	}
	v := s52.OverloadStop{ProtocolIEs: make(s52.OverloadStopIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateOverloadStopBudget(&v, budget)
	if err != nil {
		return s52.OverloadStop{}, aper.OperationError(err, "OverloadStop")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s52.OverloadStop{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "OverloadStop")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.OverloadStop{}, aper.OperationError(&s25.BuildError{Issues: issues}, "OverloadStop")
	}
	if _, err := s52.BridgeOverloadStopMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s52.OverloadStop{}, aper.OperationError(fmt.Errorf("%s %w", "OverloadStop.protocolIEs:", err), "OverloadStop")
	}
	return v, aper.OperationError(nil, "OverloadStop")
}
func NewPWSFailureIndication(fields s52.PWSFailureIndicationIEContainer, options ...aper.BuildOption) (s52.PWSFailureIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s52.PWSFailureIndication{}, aper.OperationError(err, "PWSFailureIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s52.PWSFailureIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s52.PWSFailureIndication{}, aper.OperationError(err, "PWSFailureIndication")
	}
	v := s52.PWSFailureIndication{ProtocolIEs: make(s52.PWSFailureIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidatePWSFailureIndicationBudget(&v, budget)
	if err != nil {
		return s52.PWSFailureIndication{}, aper.OperationError(err, "PWSFailureIndication")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s52.PWSFailureIndication{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "PWSFailureIndication")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s52.PWSFailureIndication{}, aper.OperationError(&s25.BuildError{Issues: issues}, "PWSFailureIndication")
	}
	if _, err := s52.BridgePWSFailureIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s52.PWSFailureIndication{}, aper.OperationError(fmt.Errorf("%s %w", "PWSFailureIndication.protocolIEs:", err), "PWSFailureIndication")
	}
	return v, aper.OperationError(nil, "PWSFailureIndication")
}
func NewRerouteNASRequest(fields s23.RerouteNASRequestIEContainer, options ...aper.BuildOption) (s31.RerouteNASRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s31.RerouteNASRequest{}, aper.OperationError(err, "RerouteNASRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s23.RerouteNASRequestIEField](bb, uint64(len(fields))); err != nil {
		return s31.RerouteNASRequest{}, aper.OperationError(err, "RerouteNASRequest")
	}
	v := s31.RerouteNASRequest{ProtocolIEs: make(s23.RerouteNASRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateRerouteNASRequestBudget(&v, budget)
	if err != nil {
		return s31.RerouteNASRequest{}, aper.OperationError(err, "RerouteNASRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s31.RerouteNASRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "RerouteNASRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s31.RerouteNASRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "RerouteNASRequest")
	}
	if _, err := s31.BridgeRerouteNASRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s31.RerouteNASRequest{}, aper.OperationError(fmt.Errorf("%s %w", "RerouteNASRequest.protocolIEs:", err), "RerouteNASRequest")
	}
	return v, aper.OperationError(nil, "RerouteNASRequest")
}
func NewConnectionEstablishmentIndication(fields s39.ConnectionEstablishmentIndicationIEContainer, options ...aper.BuildOption) (s40.ConnectionEstablishmentIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s40.ConnectionEstablishmentIndication{}, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s39.ConnectionEstablishmentIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s40.ConnectionEstablishmentIndication{}, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	v := s40.ConnectionEstablishmentIndication{ProtocolIEs: make(s39.ConnectionEstablishmentIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateConnectionEstablishmentIndicationBudget(&v, budget)
	if err != nil {
		return s40.ConnectionEstablishmentIndication{}, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s40.ConnectionEstablishmentIndication{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ConnectionEstablishmentIndication")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s40.ConnectionEstablishmentIndication{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ConnectionEstablishmentIndication")
	}
	if _, err := s40.BridgeConnectionEstablishmentIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s40.ConnectionEstablishmentIndication{}, aper.OperationError(fmt.Errorf("%s %w", "ConnectionEstablishmentIndication.protocolIEs:", err), "ConnectionEstablishmentIndication")
	}
	return v, aper.OperationError(nil, "ConnectionEstablishmentIndication")
}
func NewNASDeliveryIndication(fields s12.NASDeliveryIndicationIEContainer, options ...aper.BuildOption) (s22.NASDeliveryIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.NASDeliveryIndication{}, aper.OperationError(err, "NASDeliveryIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.NASDeliveryIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s22.NASDeliveryIndication{}, aper.OperationError(err, "NASDeliveryIndication")
	}
	v := s22.NASDeliveryIndication{ProtocolIEs: make(s12.NASDeliveryIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateNASDeliveryIndicationBudget(&v, budget)
	if err != nil {
		return s22.NASDeliveryIndication{}, aper.OperationError(err, "NASDeliveryIndication")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s22.NASDeliveryIndication{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "NASDeliveryIndication")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s22.NASDeliveryIndication{}, aper.OperationError(&s25.BuildError{Issues: issues}, "NASDeliveryIndication")
	}
	if _, err := s22.BridgeNASDeliveryIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s22.NASDeliveryIndication{}, aper.OperationError(fmt.Errorf("%s %w", "NASDeliveryIndication.protocolIEs:", err), "NASDeliveryIndication")
	}
	return v, aper.OperationError(nil, "NASDeliveryIndication")
}
func NewRetrieveUEInformation(fields s36.RetrieveUEInformationIEContainer, options ...aper.BuildOption) (s36.RetrieveUEInformation, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s36.RetrieveUEInformation{}, aper.OperationError(err, "RetrieveUEInformation")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s36.RetrieveUEInformationIEField](bb, uint64(len(fields))); err != nil {
		return s36.RetrieveUEInformation{}, aper.OperationError(err, "RetrieveUEInformation")
	}
	v := s36.RetrieveUEInformation{ProtocolIEs: make(s36.RetrieveUEInformationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateRetrieveUEInformationBudget(&v, budget)
	if err != nil {
		return s36.RetrieveUEInformation{}, aper.OperationError(err, "RetrieveUEInformation")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s36.RetrieveUEInformation{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "RetrieveUEInformation")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s36.RetrieveUEInformation{}, aper.OperationError(&s25.BuildError{Issues: issues}, "RetrieveUEInformation")
	}
	if _, err := s36.BridgeRetrieveUEInformationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s36.RetrieveUEInformation{}, aper.OperationError(fmt.Errorf("%s %w", "RetrieveUEInformation.protocolIEs:", err), "RetrieveUEInformation")
	}
	return v, aper.OperationError(nil, "RetrieveUEInformation")
}
func NewMMECPRelocationIndication(fields s11.MMECPRelocationIndicationIEContainer, options ...aper.BuildOption) (s22.MMECPRelocationIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.MMECPRelocationIndication{}, aper.OperationError(err, "MMECPRelocationIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.MMECPRelocationIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s22.MMECPRelocationIndication{}, aper.OperationError(err, "MMECPRelocationIndication")
	}
	v := s22.MMECPRelocationIndication{ProtocolIEs: make(s11.MMECPRelocationIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMECPRelocationIndicationBudget(&v, budget)
	if err != nil {
		return s22.MMECPRelocationIndication{}, aper.OperationError(err, "MMECPRelocationIndication")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s22.MMECPRelocationIndication{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "MMECPRelocationIndication")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s22.MMECPRelocationIndication{}, aper.OperationError(&s25.BuildError{Issues: issues}, "MMECPRelocationIndication")
	}
	if _, err := s22.BridgeMMECPRelocationIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s22.MMECPRelocationIndication{}, aper.OperationError(fmt.Errorf("%s %w", "MMECPRelocationIndication.protocolIEs:", err), "MMECPRelocationIndication")
	}
	return v, aper.OperationError(nil, "MMECPRelocationIndication")
}
func NewMMEEarlyStatusTransfer(fields s47.MMEEarlyStatusTransferIEContainer, options ...aper.BuildOption) (s48.MMEEarlyStatusTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s48.MMEEarlyStatusTransfer{}, aper.OperationError(err, "MMEEarlyStatusTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s47.MMEEarlyStatusTransferIEField](bb, uint64(len(fields))); err != nil {
		return s48.MMEEarlyStatusTransfer{}, aper.OperationError(err, "MMEEarlyStatusTransfer")
	}
	v := s48.MMEEarlyStatusTransfer{ProtocolIEs: make(s47.MMEEarlyStatusTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateMMEEarlyStatusTransferBudget(&v, budget)
	if err != nil {
		return s48.MMEEarlyStatusTransfer{}, aper.OperationError(err, "MMEEarlyStatusTransfer")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s48.MMEEarlyStatusTransfer{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "MMEEarlyStatusTransfer")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s48.MMEEarlyStatusTransfer{}, aper.OperationError(&s25.BuildError{Issues: issues}, "MMEEarlyStatusTransfer")
	}
	if _, err := s48.BridgeMMEEarlyStatusTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s48.MMEEarlyStatusTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "MMEEarlyStatusTransfer.protocolIEs:", err), "MMEEarlyStatusTransfer")
	}
	return v, aper.OperationError(nil, "MMEEarlyStatusTransfer")
}
func NewS1RemovalRequest(fields s24.S1RemovalRequestIEContainer, options ...aper.BuildOption) (s31.S1RemovalRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s31.S1RemovalRequest{}, aper.OperationError(err, "S1RemovalRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s24.S1RemovalRequestIEField](bb, uint64(len(fields))); err != nil {
		return s31.S1RemovalRequest{}, aper.OperationError(err, "S1RemovalRequest")
	}
	v := s31.S1RemovalRequest{ProtocolIEs: make(s24.S1RemovalRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateS1RemovalRequestBudget(&v, budget)
	if err != nil {
		return s31.S1RemovalRequest{}, aper.OperationError(err, "S1RemovalRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s31.S1RemovalRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "S1RemovalRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s31.S1RemovalRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "S1RemovalRequest")
	}
	if _, err := s31.BridgeS1RemovalRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s31.S1RemovalRequest{}, aper.OperationError(fmt.Errorf("%s %w", "S1RemovalRequest.protocolIEs:", err), "S1RemovalRequest")
	}
	return v, aper.OperationError(nil, "S1RemovalRequest")
}
func NewS1RemovalResponse(fields s27.S1RemovalResponseIEContainer, options ...aper.BuildOption) (s31.S1RemovalResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s31.S1RemovalResponse{}, aper.OperationError(err, "S1RemovalResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s27.S1RemovalResponseIEField](bb, uint64(len(fields))); err != nil {
		return s31.S1RemovalResponse{}, aper.OperationError(err, "S1RemovalResponse")
	}
	v := s31.S1RemovalResponse{ProtocolIEs: make(s27.S1RemovalResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateS1RemovalResponseBudget(&v, budget)
	if err != nil {
		return s31.S1RemovalResponse{}, aper.OperationError(err, "S1RemovalResponse")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s31.S1RemovalResponse{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "S1RemovalResponse")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s31.S1RemovalResponse{}, aper.OperationError(&s25.BuildError{Issues: issues}, "S1RemovalResponse")
	}
	if _, err := s31.BridgeS1RemovalResponseMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s31.S1RemovalResponse{}, aper.OperationError(fmt.Errorf("%s %w", "S1RemovalResponse.protocolIEs:", err), "S1RemovalResponse")
	}
	return v, aper.OperationError(nil, "S1RemovalResponse")
}
func NewS1RemovalFailure(fields s27.S1RemovalFailureIEContainer, options ...aper.BuildOption) (s31.S1RemovalFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s31.S1RemovalFailure{}, aper.OperationError(err, "S1RemovalFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s27.S1RemovalFailureIEField](bb, uint64(len(fields))); err != nil {
		return s31.S1RemovalFailure{}, aper.OperationError(err, "S1RemovalFailure")
	}
	v := s31.S1RemovalFailure{ProtocolIEs: make(s27.S1RemovalFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateS1RemovalFailureBudget(&v, budget)
	if err != nil {
		return s31.S1RemovalFailure{}, aper.OperationError(err, "S1RemovalFailure")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s31.S1RemovalFailure{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "S1RemovalFailure")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s31.S1RemovalFailure{}, aper.OperationError(&s25.BuildError{Issues: issues}, "S1RemovalFailure")
	}
	if _, err := s31.BridgeS1RemovalFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s31.S1RemovalFailure{}, aper.OperationError(fmt.Errorf("%s %w", "S1RemovalFailure.protocolIEs:", err), "S1RemovalFailure")
	}
	return v, aper.OperationError(nil, "S1RemovalFailure")
}
func BridgeValidatePathSwitchRequestFailureBudget(v *s30.PathSwitchRequestFailure, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil PathSwitchRequestFailure")
	}
	rows := []s00.FieldInfo{s27.PathSwitchRequestFailureIEs().MMEUES1APID().Info(), s27.PathSwitchRequestFailureIEs().ENBUES1APID().Info(), s27.PathSwitchRequestFailureIEs().Cause().Info(), s27.PathSwitchRequestFailureIEs().CriticalityDiagnostics().Info()}
	report := s35.BridgePathSwitchRequestFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "PathSwitchRequestFailure.protocolIEs", budget)
	BridgeWalkValidationPathSwitchRequestFailure(v, &report, "PathSwitchRequestFailure", true)
	return report, nil
}
func BridgeValidateInitialContextSetupResponseBudget(v *s50.InitialContextSetupResponse, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil InitialContextSetupResponse")
	}
	rows := []s00.FieldInfo{s50.InitialContextSetupResponseIEs().MMEUES1APID().Info(), s50.InitialContextSetupResponseIEs().ENBUES1APID().Info(), s50.InitialContextSetupResponseIEs().ERABSetupListCtxtSURes().Info(), s50.InitialContextSetupResponseIEs().ERABFailedToSetupListCtxtSURes().Info(), s50.InitialContextSetupResponseIEs().CriticalityDiagnostics().Info()}
	report := s50.BridgeInitialContextSetupResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "InitialContextSetupResponse.protocolIEs", budget)
	BridgeWalkValidationInitialContextSetupResponse(v, &report, "InitialContextSetupResponse", true)
	return report, nil
}
func BridgeValidateInitialContextSetupFailureBudget(v *s30.InitialContextSetupFailure, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil InitialContextSetupFailure")
	}
	rows := []s00.FieldInfo{s26.InitialContextSetupFailureIEs().MMEUES1APID().Info(), s26.InitialContextSetupFailureIEs().ENBUES1APID().Info(), s26.InitialContextSetupFailureIEs().Cause().Info(), s26.InitialContextSetupFailureIEs().CriticalityDiagnostics().Info()}
	report := s34.BridgeInitialContextSetupFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "InitialContextSetupFailure.protocolIEs", budget)
	BridgeWalkValidationInitialContextSetupFailure(v, &report, "InitialContextSetupFailure", true)
	return report, nil
}
func BridgeValidateDownlinkNASTransportBudget(v *s53.DownlinkNASTransport, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil DownlinkNASTransport")
	}
	rows := []s00.FieldInfo{s53.DownlinkNASTransportIEs().MMEUES1APID().Info(), s53.DownlinkNASTransportIEs().ENBUES1APID().Info(), s53.DownlinkNASTransportIEs().NASPDU().Info(), s53.DownlinkNASTransportIEs().HandoverRestrictionList().Info(), s53.DownlinkNASTransportIEs().SubscriberProfileIDforRFP().Info(), s53.DownlinkNASTransportIEs().SRVCCOperationPossible().Info(), s53.DownlinkNASTransportIEs().UERadioCapability().Info(), s53.DownlinkNASTransportIEs().DLNASPDUDeliveryAckRequest().Info(), s53.DownlinkNASTransportIEs().EnhancedCoverageRestricted().Info(), s53.DownlinkNASTransportIEs().NRUESecurityCapabilities().Info(), s53.DownlinkNASTransportIEs().CEModeBRestricted().Info(), s53.DownlinkNASTransportIEs().UECapabilityInfoRequest().Info(), s53.DownlinkNASTransportIEs().EndIndication().Info(), s53.DownlinkNASTransportIEs().PendingDataIndication().Info(), s53.DownlinkNASTransportIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s53.DownlinkNASTransportIEs().AdditionalRRMPriorityIndex().Info(), s53.DownlinkNASTransportIEs().UERadioCapabilityID().Info(), s53.DownlinkNASTransportIEs().MaskedIMEISV().Info(), s53.DownlinkNASTransportIEs().CoarseUELocation().Info()}
	report := s53.BridgeDownlinkNASTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "DownlinkNASTransport.protocolIEs", budget)
	BridgeWalkValidationDownlinkNASTransport(v, &report, "DownlinkNASTransport", true)
	return report, nil
}
func BridgeValidateErrorIndicationBudget(v *s36.ErrorIndication, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ErrorIndication")
	}
	rows := []s00.FieldInfo{s36.ErrorIndicationIEs().MMEUES1APID().Info(), s36.ErrorIndicationIEs().ENBUES1APID().Info(), s36.ErrorIndicationIEs().Cause().Info(), s36.ErrorIndicationIEs().CriticalityDiagnostics().Info(), s36.ErrorIndicationIEs().STMSI().Info()}
	report := s36.BridgeErrorIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ErrorIndication.protocolIEs", budget)
	BridgeWalkValidationErrorIndication(v, &report, "ErrorIndication", true)
	return report, nil
}
func BridgeValidateNASNonDeliveryIndicationBudget(v *s30.NASNonDeliveryIndication, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil NASNonDeliveryIndication")
	}
	rows := []s00.FieldInfo{s23.NASNonDeliveryIndicationIEs().MMEUES1APID().Info(), s23.NASNonDeliveryIndicationIEs().ENBUES1APID().Info(), s23.NASNonDeliveryIndicationIEs().NASPDU().Info(), s23.NASNonDeliveryIndicationIEs().Cause().Info()}
	report := s35.BridgeNASNonDeliveryIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "NASNonDeliveryIndication.protocolIEs", budget)
	BridgeWalkValidationNASNonDeliveryIndication(v, &report, "NASNonDeliveryIndication", true)
	return report, nil
}
func BridgeValidateS1SetupRequestBudget(v *s54.S1SetupRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1SetupRequest")
	}
	rows := []s00.FieldInfo{s54.S1SetupRequestIEs().GlobalENBID().Info(), s54.S1SetupRequestIEs().ENBname().Info(), s54.S1SetupRequestIEs().SupportedTAs().Info(), s54.S1SetupRequestIEs().DefaultPagingDRX().Info(), s54.S1SetupRequestIEs().CSGIdList().Info(), s54.S1SetupRequestIEs().UERetentionInformation().Info(), s54.S1SetupRequestIEs().NBIoTDefaultPagingDRX().Info(), s54.S1SetupRequestIEs().ConnectedengNBList().Info()}
	report := s54.BridgeS1SetupRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "S1SetupRequest.protocolIEs", budget)
	BridgeWalkValidationS1SetupRequest(v, &report, "S1SetupRequest", true)
	return report, nil
}
func BridgeValidateS1SetupResponseBudget(v *s54.S1SetupResponse, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1SetupResponse")
	}
	rows := []s00.FieldInfo{s54.S1SetupResponseIEs().MMEname().Info(), s54.S1SetupResponseIEs().ServedGUMMEIs().Info(), s54.S1SetupResponseIEs().RelativeMMECapacity().Info(), s54.S1SetupResponseIEs().MMERelaySupportIndicator().Info(), s54.S1SetupResponseIEs().CriticalityDiagnostics().Info(), s54.S1SetupResponseIEs().UERetentionInformation().Info(), s54.S1SetupResponseIEs().ServedDCNs().Info(), s54.S1SetupResponseIEs().IABSupported().Info()}
	report := s54.BridgeS1SetupResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "S1SetupResponse.protocolIEs", budget)
	BridgeWalkValidationS1SetupResponse(v, &report, "S1SetupResponse", true)
	return report, nil
}
func BridgeValidateS1SetupFailureBudget(v *s31.S1SetupFailure, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1SetupFailure")
	}
	rows := []s00.FieldInfo{s27.S1SetupFailureIEs().Cause().Info(), s27.S1SetupFailureIEs().TimeToWait().Info(), s27.S1SetupFailureIEs().CriticalityDiagnostics().Info()}
	report := s36.BridgeS1SetupFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "S1SetupFailure.protocolIEs", budget)
	BridgeWalkValidationS1SetupFailure(v, &report, "S1SetupFailure", true)
	return report, nil
}
func BridgeValidateMMEStatusTransferBudget(v *s30.MMEStatusTransfer, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEStatusTransfer")
	}
	rows := []s00.FieldInfo{s25.MMEStatusTransferIEs().MMEUES1APID().Info(), s25.MMEStatusTransferIEs().ENBUES1APID().Info(), s25.MMEStatusTransferIEs().ENBStatusTransferTransparentContainer().Info()}
	report := s35.BridgeMMEStatusTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEStatusTransfer.protocolIEs", budget)
	BridgeWalkValidationMMEStatusTransfer(v, &report, "MMEStatusTransfer", true)
	return report, nil
}
func BridgeValidateENBConfigurationUpdateBudget(v *s54.ENBConfigurationUpdate, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBConfigurationUpdate")
	}
	rows := []s00.FieldInfo{s54.ENBConfigurationUpdateIEs().ENBname().Info(), s54.ENBConfigurationUpdateIEs().SupportedTAs().Info(), s54.ENBConfigurationUpdateIEs().CSGIdList().Info(), s54.ENBConfigurationUpdateIEs().DefaultPagingDRX().Info(), s54.ENBConfigurationUpdateIEs().NBIoTDefaultPagingDRX().Info(), s54.ENBConfigurationUpdateIEs().ConnectedengNBToAddList().Info(), s54.ENBConfigurationUpdateIEs().ConnectedengNBToRemoveList().Info()}
	report := s54.BridgeENBConfigurationUpdateIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBConfigurationUpdate.protocolIEs", budget)
	BridgeWalkValidationENBConfigurationUpdate(v, &report, "ENBConfigurationUpdate", true)
	return report, nil
}
func BridgeValidateMMEConfigurationUpdateBudget(v *s54.MMEConfigurationUpdate, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEConfigurationUpdate")
	}
	rows := []s00.FieldInfo{s54.MMEConfigurationUpdateIEs().MMEname().Info(), s54.MMEConfigurationUpdateIEs().ServedGUMMEIs().Info(), s54.MMEConfigurationUpdateIEs().RelativeMMECapacity().Info(), s54.MMEConfigurationUpdateIEs().ServedDCNs().Info()}
	report := s54.BridgeMMEConfigurationUpdateIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEConfigurationUpdate.protocolIEs", budget)
	BridgeWalkValidationMMEConfigurationUpdate(v, &report, "MMEConfigurationUpdate", true)
	return report, nil
}
func BridgeValidateMMEConfigurationUpdateAcknowledgeBudget(v *s30.MMEConfigurationUpdateAcknowledge, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEConfigurationUpdateAcknowledge")
	}
	rows := []s00.FieldInfo{s26.MMEConfigurationUpdateAcknowledgeIEs().CriticalityDiagnostics().Info()}
	report := s35.BridgeMMEConfigurationUpdateAcknowledgeIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEConfigurationUpdateAcknowledge.protocolIEs", budget)
	BridgeWalkValidationMMEConfigurationUpdateAcknowledge(v, &report, "MMEConfigurationUpdateAcknowledge", true)
	return report, nil
}
func BridgeValidateMMEConfigurationUpdateFailureBudget(v *s30.MMEConfigurationUpdateFailure, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEConfigurationUpdateFailure")
	}
	rows := []s00.FieldInfo{s27.MMEConfigurationUpdateFailureIEs().Cause().Info(), s27.MMEConfigurationUpdateFailureIEs().TimeToWait().Info(), s27.MMEConfigurationUpdateFailureIEs().CriticalityDiagnostics().Info()}
	report := s35.BridgeMMEConfigurationUpdateFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEConfigurationUpdateFailure.protocolIEs", budget)
	BridgeWalkValidationMMEConfigurationUpdateFailure(v, &report, "MMEConfigurationUpdateFailure", true)
	return report, nil
}
func BridgeValidateLocationReportingControlBudget(v *s31.LocationReportingControl, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil LocationReportingControl")
	}
	rows := []s00.FieldInfo{s31.LocationReportingControlIEs().MMEUES1APID().Info(), s31.LocationReportingControlIEs().ENBUES1APID().Info(), s31.LocationReportingControlIEs().RequestType().Info()}
	report := s34.BridgeLocationReportingControlIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "LocationReportingControl.protocolIEs", budget)
	BridgeWalkValidationLocationReportingControl(v, &report, "LocationReportingControl", true)
	return report, nil
}
func BridgeValidateLocationReportingFailureIndicationBudget(v *s30.LocationReportingFailureIndication, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil LocationReportingFailureIndication")
	}
	rows := []s00.FieldInfo{s22.LocationReportingFailureIndicationIEs().MMEUES1APID().Info(), s22.LocationReportingFailureIndicationIEs().ENBUES1APID().Info(), s22.LocationReportingFailureIndicationIEs().Cause().Info()}
	report := s34.BridgeLocationReportingFailureIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "LocationReportingFailureIndication.protocolIEs", budget)
	BridgeWalkValidationLocationReportingFailureIndication(v, &report, "LocationReportingFailureIndication", true)
	return report, nil
}
func BridgeValidateLocationReportBudget(v *s42.LocationReport, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil LocationReport")
	}
	rows := []s00.FieldInfo{s41.LocationReportIEs().MMEUES1APID().Info(), s41.LocationReportIEs().ENBUES1APID().Info(), s41.LocationReportIEs().EUTRANCGI().Info(), s41.LocationReportIEs().TAI().Info(), s41.LocationReportIEs().RequestType().Info(), s41.LocationReportIEs().PSCellInformation().Info(), s41.LocationReportIEs().LTENTNTAIInformation().Info()}
	report := s42.BridgeLocationReportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "LocationReport.protocolIEs", budget)
	BridgeWalkValidationLocationReport(v, &report, "LocationReport", true)
	return report, nil
}
func BridgeValidateOverloadStartBudget(v *s52.OverloadStart, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil OverloadStart")
	}
	rows := []s00.FieldInfo{s52.OverloadStartIEs().OverloadResponse().Info(), s52.OverloadStartIEs().GUMMEIList().Info(), s52.OverloadStartIEs().TrafficLoadReductionIndication().Info()}
	report := s52.BridgeOverloadStartIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "OverloadStart.protocolIEs", budget)
	BridgeWalkValidationOverloadStart(v, &report, "OverloadStart", true)
	return report, nil
}
func BridgeValidateOverloadStopBudget(v *s52.OverloadStop, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil OverloadStop")
	}
	rows := []s00.FieldInfo{s52.OverloadStopIEs().GUMMEIList().Info()}
	report := s52.BridgeOverloadStopIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "OverloadStop.protocolIEs", budget)
	BridgeWalkValidationOverloadStop(v, &report, "OverloadStop", true)
	return report, nil
}
func BridgeValidatePWSFailureIndicationBudget(v *s52.PWSFailureIndication, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil PWSFailureIndication")
	}
	rows := []s00.FieldInfo{s52.PWSFailureIndicationIEs().PWSfailedECGIList().Info(), s52.PWSFailureIndicationIEs().GlobalENBID().Info()}
	report := s53.BridgePWSFailureIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "PWSFailureIndication.protocolIEs", budget)
	BridgeWalkValidationPWSFailureIndication(v, &report, "PWSFailureIndication", true)
	return report, nil
}
func BridgeValidateRerouteNASRequestBudget(v *s31.RerouteNASRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil RerouteNASRequest")
	}
	rows := []s00.FieldInfo{s24.RerouteNASRequestIEs().ENBUES1APID().Info(), s24.RerouteNASRequestIEs().MMEUES1APID().Info(), s24.RerouteNASRequestIEs().S1Message().Info(), s24.RerouteNASRequestIEs().MMEGroupID().Info(), s24.RerouteNASRequestIEs().AdditionalGUTI().Info(), s24.RerouteNASRequestIEs().UEUsageType().Info()}
	report := s36.BridgeRerouteNASRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "RerouteNASRequest.protocolIEs", budget)
	BridgeWalkValidationRerouteNASRequest(v, &report, "RerouteNASRequest", true)
	return report, nil
}
func BridgeValidateConnectionEstablishmentIndicationBudget(v *s40.ConnectionEstablishmentIndication, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ConnectionEstablishmentIndication")
	}
	rows := []s00.FieldInfo{s39.ConnectionEstablishmentIndicationIEs().MMEUES1APID().Info(), s39.ConnectionEstablishmentIndicationIEs().ENBUES1APID().Info(), s39.ConnectionEstablishmentIndicationIEs().UERadioCapability().Info(), s39.ConnectionEstablishmentIndicationIEs().EnhancedCoverageRestricted().Info(), s39.ConnectionEstablishmentIndicationIEs().DLCPSecurityInformation().Info(), s39.ConnectionEstablishmentIndicationIEs().CEModeBRestricted().Info(), s39.ConnectionEstablishmentIndicationIEs().EndIndication().Info(), s39.ConnectionEstablishmentIndicationIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s39.ConnectionEstablishmentIndicationIEs().UELevelQoSParameters().Info(), s39.ConnectionEstablishmentIndicationIEs().UERadioCapabilityID().Info(), s39.ConnectionEstablishmentIndicationIEs().MaskedIMEISV().Info(), s39.ConnectionEstablishmentIndicationIEs().CoarseUELocation().Info()}
	report := s40.BridgeConnectionEstablishmentIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ConnectionEstablishmentIndication.protocolIEs", budget)
	BridgeWalkValidationConnectionEstablishmentIndication(v, &report, "ConnectionEstablishmentIndication", true)
	return report, nil
}
func BridgeValidateNASDeliveryIndicationBudget(v *s22.NASDeliveryIndication, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil NASDeliveryIndication")
	}
	rows := []s00.FieldInfo{s12.NASDeliveryIndicationIEs().MMEUES1APID().Info(), s12.NASDeliveryIndicationIEs().ENBUES1APID().Info()}
	report := s35.BridgeNASDeliveryIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "NASDeliveryIndication.protocolIEs", budget)
	BridgeWalkValidationNASDeliveryIndication(v, &report, "NASDeliveryIndication", true)
	return report, nil
}
func BridgeValidateRetrieveUEInformationBudget(v *s36.RetrieveUEInformation, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil RetrieveUEInformation")
	}
	rows := []s00.FieldInfo{s36.RetrieveUEInformationIEs().STMSI().Info()}
	report := s36.BridgeRetrieveUEInformationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "RetrieveUEInformation.protocolIEs", budget)
	BridgeWalkValidationRetrieveUEInformation(v, &report, "RetrieveUEInformation", true)
	return report, nil
}
func BridgeValidateMMECPRelocationIndicationBudget(v *s22.MMECPRelocationIndication, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMECPRelocationIndication")
	}
	rows := []s00.FieldInfo{s12.MMECPRelocationIndicationIEs().MMEUES1APID().Info(), s12.MMECPRelocationIndicationIEs().ENBUES1APID().Info()}
	report := s35.BridgeMMECPRelocationIndicationIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMECPRelocationIndication.protocolIEs", budget)
	BridgeWalkValidationMMECPRelocationIndication(v, &report, "MMECPRelocationIndication", true)
	return report, nil
}
func BridgeValidateMMEEarlyStatusTransferBudget(v *s48.MMEEarlyStatusTransfer, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil MMEEarlyStatusTransfer")
	}
	rows := []s00.FieldInfo{s47.MMEEarlyStatusTransferIEs().MMEUES1APID().Info(), s47.MMEEarlyStatusTransferIEs().ENBUES1APID().Info(), s47.MMEEarlyStatusTransferIEs().ENBEarlyStatusTransferTransparentContainer().Info()}
	report := s48.BridgeMMEEarlyStatusTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "MMEEarlyStatusTransfer.protocolIEs", budget)
	BridgeWalkValidationMMEEarlyStatusTransfer(v, &report, "MMEEarlyStatusTransfer", true)
	return report, nil
}
func BridgeValidateS1RemovalRequestBudget(v *s31.S1RemovalRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1RemovalRequest")
	}
	rows := []s00.FieldInfo{s24.S1RemovalRequestIEs().GlobalENBID().Info()}
	report := s36.BridgeS1RemovalRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "S1RemovalRequest.protocolIEs", budget)
	BridgeWalkValidationS1RemovalRequest(v, &report, "S1RemovalRequest", true)
	return report, nil
}
func BridgeValidateS1RemovalResponseBudget(v *s31.S1RemovalResponse, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1RemovalResponse")
	}
	rows := []s00.FieldInfo{s27.S1RemovalResponseIEs().MMEname().Info(), s27.S1RemovalResponseIEs().CriticalityDiagnostics().Info()}
	report := s36.BridgeS1RemovalResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "S1RemovalResponse.protocolIEs", budget)
	BridgeWalkValidationS1RemovalResponse(v, &report, "S1RemovalResponse", true)
	return report, nil
}
func BridgeValidateS1RemovalFailureBudget(v *s31.S1RemovalFailure, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil S1RemovalFailure")
	}
	rows := []s00.FieldInfo{s27.S1RemovalFailureIEs().Cause().Info(), s27.S1RemovalFailureIEs().CriticalityDiagnostics().Info()}
	report := s36.BridgeS1RemovalFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "S1RemovalFailure.protocolIEs", budget)
	BridgeWalkValidationS1RemovalFailure(v, &report, "S1RemovalFailure", true)
	return report, nil
}
func ValidatePathSwitchRequestFailure(v *s30.PathSwitchRequestFailure, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "PathSwitchRequestFailure")
	}
	report, err := BridgeValidatePathSwitchRequestFailureBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s30.BridgePathSwitchRequestFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PathSwitchRequestFailure")
}
func ValidateInitialContextSetupResponse(v *s50.InitialContextSetupResponse, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "InitialContextSetupResponse")
	}
	report, err := BridgeValidateInitialContextSetupResponseBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s50.BridgeInitialContextSetupResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "InitialContextSetupResponse")
}
func ValidateInitialContextSetupFailure(v *s30.InitialContextSetupFailure, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "InitialContextSetupFailure")
	}
	report, err := BridgeValidateInitialContextSetupFailureBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s30.BridgeInitialContextSetupFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "InitialContextSetupFailure")
}
func ValidateDownlinkNASTransport(v *s53.DownlinkNASTransport, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "DownlinkNASTransport")
	}
	report, err := BridgeValidateDownlinkNASTransportBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s53.BridgeDownlinkNASTransportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "DownlinkNASTransport")
}
func ValidateErrorIndication(v *s36.ErrorIndication, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ErrorIndication")
	}
	report, err := BridgeValidateErrorIndicationBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeErrorIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ErrorIndication")
}
func ValidateNASNonDeliveryIndication(v *s30.NASNonDeliveryIndication, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "NASNonDeliveryIndication")
	}
	report, err := BridgeValidateNASNonDeliveryIndicationBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s30.BridgeNASNonDeliveryIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "NASNonDeliveryIndication")
}
func ValidateS1SetupRequest(v *s54.S1SetupRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "S1SetupRequest")
	}
	report, err := BridgeValidateS1SetupRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s54.BridgeS1SetupRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "S1SetupRequest")
}
func ValidateS1SetupResponse(v *s54.S1SetupResponse, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "S1SetupResponse")
	}
	report, err := BridgeValidateS1SetupResponseBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s54.BridgeS1SetupResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "S1SetupResponse")
}
func ValidateS1SetupFailure(v *s31.S1SetupFailure, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "S1SetupFailure")
	}
	report, err := BridgeValidateS1SetupFailureBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s31.BridgeS1SetupFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "S1SetupFailure")
}
func ValidateMMEStatusTransfer(v *s30.MMEStatusTransfer, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "MMEStatusTransfer")
	}
	report, err := BridgeValidateMMEStatusTransferBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s30.BridgeMMEStatusTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEStatusTransfer")
}
func ValidateENBConfigurationUpdate(v *s54.ENBConfigurationUpdate, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ENBConfigurationUpdate")
	}
	report, err := BridgeValidateENBConfigurationUpdateBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s54.BridgeENBConfigurationUpdateMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBConfigurationUpdate")
}
func ValidateMMEConfigurationUpdate(v *s54.MMEConfigurationUpdate, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "MMEConfigurationUpdate")
	}
	report, err := BridgeValidateMMEConfigurationUpdateBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s54.BridgeMMEConfigurationUpdateMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEConfigurationUpdate")
}
func ValidateMMEConfigurationUpdateAcknowledge(v *s30.MMEConfigurationUpdateAcknowledge, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "MMEConfigurationUpdateAcknowledge")
	}
	report, err := BridgeValidateMMEConfigurationUpdateAcknowledgeBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s30.BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEConfigurationUpdateAcknowledge")
}
func ValidateMMEConfigurationUpdateFailure(v *s30.MMEConfigurationUpdateFailure, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "MMEConfigurationUpdateFailure")
	}
	report, err := BridgeValidateMMEConfigurationUpdateFailureBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s30.BridgeMMEConfigurationUpdateFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEConfigurationUpdateFailure")
}
func ValidateLocationReportingControl(v *s31.LocationReportingControl, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "LocationReportingControl")
	}
	report, err := BridgeValidateLocationReportingControlBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s31.BridgeLocationReportingControlMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "LocationReportingControl")
}
func ValidateLocationReportingFailureIndication(v *s30.LocationReportingFailureIndication, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "LocationReportingFailureIndication")
	}
	report, err := BridgeValidateLocationReportingFailureIndicationBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s30.BridgeLocationReportingFailureIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "LocationReportingFailureIndication")
}
func ValidateLocationReport(v *s42.LocationReport, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "LocationReport")
	}
	report, err := BridgeValidateLocationReportBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s42.BridgeLocationReportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "LocationReport")
}
func ValidateOverloadStart(v *s52.OverloadStart, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "OverloadStart")
	}
	report, err := BridgeValidateOverloadStartBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s52.BridgeOverloadStartMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "OverloadStart")
}
func ValidateOverloadStop(v *s52.OverloadStop, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "OverloadStop")
	}
	report, err := BridgeValidateOverloadStopBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s52.BridgeOverloadStopMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "OverloadStop")
}
func ValidatePWSFailureIndication(v *s52.PWSFailureIndication, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "PWSFailureIndication")
	}
	report, err := BridgeValidatePWSFailureIndicationBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s52.BridgePWSFailureIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PWSFailureIndication")
}
func ValidateRerouteNASRequest(v *s31.RerouteNASRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "RerouteNASRequest")
	}
	report, err := BridgeValidateRerouteNASRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s31.BridgeRerouteNASRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "RerouteNASRequest")
}
func ValidateConnectionEstablishmentIndication(v *s40.ConnectionEstablishmentIndication, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ConnectionEstablishmentIndication")
	}
	report, err := BridgeValidateConnectionEstablishmentIndicationBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s40.BridgeConnectionEstablishmentIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ConnectionEstablishmentIndication")
}
func ValidateNASDeliveryIndication(v *s22.NASDeliveryIndication, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "NASDeliveryIndication")
	}
	report, err := BridgeValidateNASDeliveryIndicationBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s22.BridgeNASDeliveryIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "NASDeliveryIndication")
}
func ValidateRetrieveUEInformation(v *s36.RetrieveUEInformation, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "RetrieveUEInformation")
	}
	report, err := BridgeValidateRetrieveUEInformationBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s36.BridgeRetrieveUEInformationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "RetrieveUEInformation")
}
func ValidateMMECPRelocationIndication(v *s22.MMECPRelocationIndication, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "MMECPRelocationIndication")
	}
	report, err := BridgeValidateMMECPRelocationIndicationBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s22.BridgeMMECPRelocationIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMECPRelocationIndication")
}
func ValidateMMEEarlyStatusTransfer(v *s48.MMEEarlyStatusTransfer, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "MMEEarlyStatusTransfer")
	}
	report, err := BridgeValidateMMEEarlyStatusTransferBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s48.BridgeMMEEarlyStatusTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "MMEEarlyStatusTransfer")
}
func ValidateS1RemovalRequest(v *s31.S1RemovalRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "S1RemovalRequest")
	}
	report, err := BridgeValidateS1RemovalRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s31.BridgeS1RemovalRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "S1RemovalRequest")
}
func ValidateS1RemovalResponse(v *s31.S1RemovalResponse, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "S1RemovalResponse")
	}
	report, err := BridgeValidateS1RemovalResponseBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s31.BridgeS1RemovalResponseMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "S1RemovalResponse")
}
func ValidateS1RemovalFailure(v *s31.S1RemovalFailure, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "S1RemovalFailure")
	}
	report, err := BridgeValidateS1RemovalFailureBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s31.BridgeS1RemovalFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "S1RemovalFailure")
}
func BridgeWalkValidationAssistanceDataForPaging(v *s31.AssistanceDataForPaging, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.AssistanceDataForRecommendedCells != nil {
		BridgeWalkValidationAssistanceDataForRecommendedCells(v.AssistanceDataForRecommendedCells, report, path+".assistanceDataForRecommendedCells", false)
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.AssistanceDataForCECapableUEs != nil {
		s61.BridgeWalkValidationAssistanceDataForCECapableUEs(v.AssistanceDataForCECapableUEs, report, path+".assistanceDataForCECapableUEs", false)
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.PagingAttemptInformation != nil {
		BridgeWalkValidationPagingAttemptInformation(v.PagingAttemptInformation, report, path+".pagingAttemptInformation", false)
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
				s30.BridgeMergeNestedValidation(report, s31.BridgeAssistanceDataForPagingExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationAssistanceDataForRecommendedCells(v *s31.AssistanceDataForRecommendedCells, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationRecommendedCellsForPaging(&v.RecommendedCellsForPaging, report, path+".recommendedCellsForPaging", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s31.BridgeAssistanceDataForRecommendedCellsExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationBroadcastCompletedAreaList(v *s41.BroadcastCompletedAreaList, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.BroadcastCompletedAreaListChoiceCellIDBroadcast && v.CellIDBroadcast != nil {
		s61.BridgeWalkValidationCellIDBroadcast(&v.CellIDBroadcast, report, path+".cellID-Broadcast", false)
	}
	if v.Choice == s00.BroadcastCompletedAreaListChoiceTAIBroadcast && v.TAIBroadcast != nil {
		BridgeWalkValidationTAIBroadcast(&v.TAIBroadcast, report, path+".tAI-Broadcast", false)
	}
	if v.Choice == s00.BroadcastCompletedAreaListChoiceEmergencyAreaIDBroadcast && v.EmergencyAreaIDBroadcast != nil {
		s61.BridgeWalkValidationEmergencyAreaIDBroadcast(&v.EmergencyAreaIDBroadcast, report, path+".emergencyAreaID-Broadcast", false)
	}
}
func BridgeWalkValidationCellStateIndication(v *s28.CellStateIndication, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationNotificationCellList(&v.NotificationCellList, report, path+".notificationCellList", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationConnectedengNBItem(v *s40.ConnectedengNBItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationSupportedTAs(&v.SupportedTAs, report, path+".supportedTAs", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s32.BridgeConnectedengNBItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationConnectedengNBList(v *s40.ConnectedengNBList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationConnectedengNBItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationConnectionEstablishmentIndication(v *s40.ConnectionEstablishmentIndication, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s39.ConnectionEstablishmentIndicationIEs().MMEUES1APID().Info(), s39.ConnectionEstablishmentIndicationIEs().ENBUES1APID().Info(), s39.ConnectionEstablishmentIndicationIEs().UERadioCapability().Info(), s39.ConnectionEstablishmentIndicationIEs().EnhancedCoverageRestricted().Info(), s39.ConnectionEstablishmentIndicationIEs().DLCPSecurityInformation().Info(), s39.ConnectionEstablishmentIndicationIEs().CEModeBRestricted().Info(), s39.ConnectionEstablishmentIndicationIEs().EndIndication().Info(), s39.ConnectionEstablishmentIndicationIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s39.ConnectionEstablishmentIndicationIEs().UELevelQoSParameters().Info(), s39.ConnectionEstablishmentIndicationIEs().UERadioCapabilityID().Info(), s39.ConnectionEstablishmentIndicationIEs().MaskedIMEISV().Info(), s39.ConnectionEstablishmentIndicationIEs().CoarseUELocation().Info()}
			s30.BridgeMergeNestedValidation(report, s40.BridgeConnectionEstablishmentIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(253):
				if value, ok := fields[i].Value.AsDLCPSecurityInformation(); ok {
					s61.BridgeWalkValidationDLCPSecurityInformation(value, report, fmt.Sprintf("%s[%d]{id=253}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(252):
				if value, ok := fields[i].Value.AsUELevelQoSParameters(); ok {
					s61.BridgeWalkValidationERABLevelQoSParameters(value, report, fmt.Sprintf("%s[%d]{id=252}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationContextatSource(v *s23.ContextatSource, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationGlobalRANNODEID(&v.SourceNGRANNodeID, report, path+".sourceNG-RAN-node-ID", false)
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
				s30.BridgeMergeNestedValidation(report, s32.BridgeContextatSourceExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationDownlinkNASTransport(v *s53.DownlinkNASTransport, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s53.DownlinkNASTransportIEs().MMEUES1APID().Info(), s53.DownlinkNASTransportIEs().ENBUES1APID().Info(), s53.DownlinkNASTransportIEs().NASPDU().Info(), s53.DownlinkNASTransportIEs().HandoverRestrictionList().Info(), s53.DownlinkNASTransportIEs().SubscriberProfileIDforRFP().Info(), s53.DownlinkNASTransportIEs().SRVCCOperationPossible().Info(), s53.DownlinkNASTransportIEs().UERadioCapability().Info(), s53.DownlinkNASTransportIEs().DLNASPDUDeliveryAckRequest().Info(), s53.DownlinkNASTransportIEs().EnhancedCoverageRestricted().Info(), s53.DownlinkNASTransportIEs().NRUESecurityCapabilities().Info(), s53.DownlinkNASTransportIEs().CEModeBRestricted().Info(), s53.DownlinkNASTransportIEs().UECapabilityInfoRequest().Info(), s53.DownlinkNASTransportIEs().EndIndication().Info(), s53.DownlinkNASTransportIEs().PendingDataIndication().Info(), s53.DownlinkNASTransportIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s53.DownlinkNASTransportIEs().AdditionalRRMPriorityIndex().Info(), s53.DownlinkNASTransportIEs().UERadioCapabilityID().Info(), s53.DownlinkNASTransportIEs().MaskedIMEISV().Info(), s53.DownlinkNASTransportIEs().CoarseUELocation().Info()}
			s30.BridgeMergeNestedValidation(report, s53.BridgeDownlinkNASTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(41):
				if value, ok := fields[i].Value.AsHandoverRestrictionList(); ok {
					BridgeWalkValidationHandoverRestrictionList(value, report, fmt.Sprintf("%s[%d]{id=41}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(269):
				if value, ok := fields[i].Value.AsNRUESecurityCapabilities(); ok {
					BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBConfigurationUpdate(v *s54.ENBConfigurationUpdate, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s54.ENBConfigurationUpdateIEs().ENBname().Info(), s54.ENBConfigurationUpdateIEs().SupportedTAs().Info(), s54.ENBConfigurationUpdateIEs().CSGIdList().Info(), s54.ENBConfigurationUpdateIEs().DefaultPagingDRX().Info(), s54.ENBConfigurationUpdateIEs().NBIoTDefaultPagingDRX().Info(), s54.ENBConfigurationUpdateIEs().ConnectedengNBToAddList().Info(), s54.ENBConfigurationUpdateIEs().ConnectedengNBToRemoveList().Info()}
			s30.BridgeMergeNestedValidation(report, s54.BridgeENBConfigurationUpdateIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(64):
				if value, ok := fields[i].Value.AsSupportedTAs(); ok {
					BridgeWalkValidationSupportedTAs(value, report, fmt.Sprintf("%s[%d]{id=64}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(128):
				if value, ok := fields[i].Value.AsCSGIdList(); ok {
					s61.BridgeWalkValidationCSGIdList(value, report, fmt.Sprintf("%s[%d]{id=128}", nestedPath, i), false)
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
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENDCSONTransferType(v *s40.ENDCSONTransferType, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
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
func BridgeWalkValidationENDCSONeNBIdentification(v *s40.ENDCSONeNBIdentification, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s61.BridgeWalkValidationGlobalENBID(&v.GlobaleNBID, report, path+".globaleNBID", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationTAI(&v.SelectedTAI, report, path+".selectedTAI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s32.BridgeENDCSONeNBIdentificationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationENDCSONengNBIdentification(v *s40.ENDCSONengNBIdentification, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s61.BridgeWalkValidationGlobalEnGNBID(&v.GlobalengNBID, report, path+".globalengNBID", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationTAI(&v.SelectedTAI, report, path+".selectedTAI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s32.BridgeENDCSONengNBIdentificationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationENDCTransferTypeReply(v *s40.ENDCTransferTypeReply, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationENDCSONengNBIdentification(&v.SourceengNB, report, path+".sourceengNB", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationENDCSONeNBIdentification(&v.TargeteNB, report, path+".targeteNB", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s32.BridgeENDCTransferTypeReplyExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationENDCTransferTypeRequest(v *s40.ENDCTransferTypeRequest, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationENDCSONeNBIdentification(&v.SourceeNB, report, path+".sourceeNB", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationENDCSONengNBIdentification(&v.TargetengNB, report, path+".targetengNB", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.TargeteNB != nil {
		BridgeWalkValidationENDCSONeNBIdentification(v.TargeteNB, report, path+".targeteNB", false)
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.AssociatedTAI != nil {
		BridgeWalkValidationTAI(v.AssociatedTAI, report, path+".associatedTAI", false)
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.Broadcast5GSTAI != nil {
		s61.BridgeWalkValidationFiveGSTAI(v.Broadcast5GSTAI, report, path+".broadcast5GSTAI", false)
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
				s30.BridgeMergeNestedValidation(report, s32.BridgeENDCTransferTypeRequestExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABInformationList(v *s37.ERABInformationList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s37.ERABInformationListIEs().ERABInformationListItem().Info()}
		s30.BridgeMergeNestedValidation(report, s37.BridgeERABInformationListIEValueValidateS1APIEContainer(s37.ERABInformationListIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s37.ERABInformationListIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(78):
				if value, ok := fields[i].Value.AsERABInformationListItem(); ok {
					BridgeWalkValidationERABInformationListItem(value, report, fmt.Sprintf("%s[%d]{id=78}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABInformationListItem(v *s37.ERABInformationListItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
				rows := []s00.FieldInfo{s00.FieldInfo(s37.ERABInformationListItemExtIEs().DAPSRequestInfo().Info()), s00.FieldInfo(s37.ERABInformationListItemExtIEs().SourceTransportLayerAddress().Info()), s00.FieldInfo(s37.ERABInformationListItemExtIEs().SecurityIndication().Info()), s00.FieldInfo(s37.ERABInformationListItemExtIEs().SourceNodeTransportLayerAddress().Info())}
				s30.BridgeMergeNestedValidation(report, s37.BridgeERABInformationListItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(317):
					if value, ok := fields[i].ExtensionValue.AsDAPSRequestInfo(); ok {
						s61.BridgeWalkValidationDAPSRequestInfo(value, report, fmt.Sprintf("%s[%d]{id=317}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(332):
					if value, ok := fields[i].ExtensionValue.AsSecurityIndication(); ok {
						BridgeWalkValidationSecurityIndication(value, report, fmt.Sprintf("%s[%d]{id=332}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABSecurityResultItem(v *s38.ERABSecurityResultItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationSecurityResult(&v.SecurityResult, report, path+".securityResult", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABSecurityResultItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABSecurityResultList(v *s38.ERABSecurityResultList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s38.ERABSecurityResultListIEs().ERABSecurityResultItem().Info()}
		s30.BridgeMergeNestedValidation(report, s39.BridgeERABSecurityResultListIEValueValidateS1APIEContainer(s38.ERABSecurityResultListIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s38.ERABSecurityResultListIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
func BridgeWalkValidationERABToBeSetupItemBearerSUReq(v *s37.ERABToBeSetupItemBearerSUReq, report *s25.ValidationReport, path string, skipRoot bool) {
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
	s61.BridgeWalkValidationERABLevelQoSParameters(&v.ERABlevelQoSParameters, report, path+".e-RABlevelQoSParameters", false)
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
				rows := []s00.FieldInfo{s00.FieldInfo(s37.ERABToBeSetupItemBearerSUReqExtIEs().CorrelationID().Info()), s00.FieldInfo(s37.ERABToBeSetupItemBearerSUReqExtIEs().SIPTOCorrelationID().Info()), s00.FieldInfo(s37.ERABToBeSetupItemBearerSUReqExtIEs().BearerType().Info()), s00.FieldInfo(s37.ERABToBeSetupItemBearerSUReqExtIEs().EthernetType().Info()), s00.FieldInfo(s37.ERABToBeSetupItemBearerSUReqExtIEs().SecurityIndication().Info())}
				s30.BridgeMergeNestedValidation(report, s38.BridgeERABToBeSetupItemBearerSUReqExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(332):
					if value, ok := fields[i].ExtensionValue.AsSecurityIndication(); ok {
						BridgeWalkValidationSecurityIndication(value, report, fmt.Sprintf("%s[%d]{id=332}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeSetupItemCtxtSUReq(v *s38.ERABToBeSetupItemCtxtSUReq, report *s25.ValidationReport, path string, skipRoot bool) {
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
	s61.BridgeWalkValidationERABLevelQoSParameters(&v.ERABlevelQoSParameters, report, path+".e-RABlevelQoSParameters", false)
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
				rows := []s00.FieldInfo{s00.FieldInfo(s37.ERABToBeSetupItemCtxtSUReqExtIEs().CorrelationID().Info()), s00.FieldInfo(s37.ERABToBeSetupItemCtxtSUReqExtIEs().SIPTOCorrelationID().Info()), s00.FieldInfo(s37.ERABToBeSetupItemCtxtSUReqExtIEs().BearerType().Info()), s00.FieldInfo(s37.ERABToBeSetupItemCtxtSUReqExtIEs().EthernetType().Info()), s00.FieldInfo(s37.ERABToBeSetupItemCtxtSUReqExtIEs().SecurityIndication().Info())}
				s30.BridgeMergeNestedValidation(report, s38.BridgeERABToBeSetupItemCtxtSUReqExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(332):
					if value, ok := fields[i].ExtensionValue.AsSecurityIndication(); ok {
						BridgeWalkValidationSecurityIndication(value, report, fmt.Sprintf("%s[%d]{id=332}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeSetupItemHOReq(v *s38.ERABToBeSetupItemHOReq, report *s25.ValidationReport, path string, skipRoot bool) {
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
	s61.BridgeWalkValidationERABLevelQoSParameters(&v.ERABlevelQosParameters, report, path+".e-RABlevelQosParameters", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s37.ERABToBeSetupItemHOReqExtIEs().DataForwardingNotPossible().Info()), s00.FieldInfo(s37.ERABToBeSetupItemHOReqExtIEs().BearerType().Info()), s00.FieldInfo(s37.ERABToBeSetupItemHOReqExtIEs().EthernetType().Info()), s00.FieldInfo(s37.ERABToBeSetupItemHOReqExtIEs().SecurityIndication().Info())}
				s30.BridgeMergeNestedValidation(report, s38.BridgeERABToBeSetupItemHOReqExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(332):
					if value, ok := fields[i].ExtensionValue.AsSecurityIndication(); ok {
						BridgeWalkValidationSecurityIndication(value, report, fmt.Sprintf("%s[%d]{id=332}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeSetupListBearerSUReq(v *s38.ERABToBeSetupListBearerSUReq, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s38.ERABToBeSetupItemBearerSUReqIEs().ERABToBeSetupItemBearerSUReq().Info()}
		s30.BridgeMergeNestedValidation(report, s38.BridgeERABToBeSetupItemBearerSUReqIEValueValidateS1APIEContainer(s38.ERABToBeSetupItemBearerSUReqIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s38.ERABToBeSetupItemBearerSUReqIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(17):
				if value, ok := fields[i].Value.AsERABToBeSetupItemBearerSUReq(); ok {
					BridgeWalkValidationERABToBeSetupItemBearerSUReq(value, report, fmt.Sprintf("%s[%d]{id=17}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeSetupListCtxtSUReq(v *s38.ERABToBeSetupListCtxtSUReq, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s38.ERABToBeSetupItemCtxtSUReqIEs().ERABToBeSetupItemCtxtSUReq().Info()}
		s30.BridgeMergeNestedValidation(report, s38.BridgeERABToBeSetupItemCtxtSUReqIEValueValidateS1APIEContainer(s38.ERABToBeSetupItemCtxtSUReqIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s38.ERABToBeSetupItemCtxtSUReqIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
func BridgeWalkValidationERABToBeSetupListHOReq(v *s38.ERABToBeSetupListHOReq, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s38.ERABToBeSetupItemHOReqIEs().ERABToBeSetupItemHOReq().Info()}
		s30.BridgeMergeNestedValidation(report, s38.BridgeERABToBeSetupItemHOReqIEValueValidateS1APIEContainer(s38.ERABToBeSetupItemHOReqIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s38.ERABToBeSetupItemHOReqIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
func BridgeWalkValidationERABToBeSwitchedDLItem(v *s38.ERABToBeSwitchedDLItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s37.ERABToBeSwitchedDLItemExtIEs().SecurityIndication().Info())}
				s30.BridgeMergeNestedValidation(report, s38.BridgeERABToBeSwitchedDLItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(332):
					if value, ok := fields[i].ExtensionValue.AsSecurityIndication(); ok {
						BridgeWalkValidationSecurityIndication(value, report, fmt.Sprintf("%s[%d]{id=332}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABToBeSwitchedDLList(v *s38.ERABToBeSwitchedDLList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s38.ERABToBeSwitchedDLItemIEs().ERABToBeSwitchedDLItem().Info()}
		s30.BridgeMergeNestedValidation(report, s38.BridgeERABToBeSwitchedDLItemIEValueValidateS1APIEContainer(s38.ERABToBeSwitchedDLItemIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s38.ERABToBeSwitchedDLItemIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
func BridgeWalkValidationERABToBeUpdatedItem(v *s37.ERABToBeUpdatedItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.SecurityIndication != nil {
		BridgeWalkValidationSecurityIndication(v.SecurityIndication, report, path+".securityIndication", false)
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
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABToBeUpdatedItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABToBeUpdatedList(v *s37.ERABToBeUpdatedList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s37.ERABToBeUpdatedItemIEs().ERABToBeUpdatedItem().Info()}
		s30.BridgeMergeNestedValidation(report, s38.BridgeERABToBeUpdatedItemIEValueValidateS1APIEContainer(s37.ERABToBeUpdatedItemIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s37.ERABToBeUpdatedItemIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
func BridgeWalkValidationErrorIndication(v *s36.ErrorIndication, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s36.ErrorIndicationIEs().MMEUES1APID().Info(), s36.ErrorIndicationIEs().ENBUES1APID().Info(), s36.ErrorIndicationIEs().Cause().Info(), s36.ErrorIndicationIEs().CriticalityDiagnostics().Info(), s36.ErrorIndicationIEs().STMSI().Info()}
			s30.BridgeMergeNestedValidation(report, s36.BridgeErrorIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
			case s00.ProtocolIEID(96):
				if value, ok := fields[i].Value.AsSTMSI(); ok {
					BridgeWalkValidationSTMSI(value, report, fmt.Sprintf("%s[%d]{id=96}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEventL1LoggedMDTConfig(v *s22.EventL1LoggedMDTConfig, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationMeasurementThresholdL1LoggedMDT(&v.L1Threshold, report, path+".l1Threshold", false)
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
				s30.BridgeMergeNestedValidation(report, s34.BridgeEventL1LoggedMDTConfigExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationEventTrigger(v *s22.EventTrigger, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.EventTriggerChoiceEventL1LoggedMDTConfig && v.EventL1LoggedMDTConfig != nil {
		BridgeWalkValidationEventL1LoggedMDTConfig(v.EventL1LoggedMDTConfig, report, path+".eventL1LoggedMDTConfig", false)
	}
}
func BridgeWalkValidationGERANCellID(v *s22.GERANCellID, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationLAI(&v.LAI, report, path+".lAI", false)
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
				s30.BridgeMergeNestedValidation(report, s34.BridgeGERANCellIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationGlobalRANNODEID(v *s23.GlobalRANNODEID, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.GlobalRANNODEIDChoiceGNB && v.GNB != nil {
		s61.BridgeWalkValidationGNB(v.GNB, report, path+".gNB", false)
	}
	if v.Choice == s00.GlobalRANNODEIDChoiceNgENB && v.NgENB != nil {
		BridgeWalkValidationNGENB(v.NgENB, report, path+".ng-eNB", false)
	}
}
func BridgeWalkValidationHandoverRestrictionList(v *s53.HandoverRestrictionList, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.EquivalentPLMNs != nil {
		s61.BridgeWalkValidationEPLMNs(&v.EquivalentPLMNs, report, path+".equivalentPLMNs", false)
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.ForbiddenTAs != nil {
		s61.BridgeWalkValidationForbiddenTAs(&v.ForbiddenTAs, report, path+".forbiddenTAs", false)
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.ForbiddenLAs != nil {
		s61.BridgeWalkValidationForbiddenLAs(&v.ForbiddenLAs, report, path+".forbiddenLAs", false)
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
				rows := []s00.FieldInfo{s00.FieldInfo(s53.HandoverRestrictionListExtIEs().NRrestrictioninEPSasSecondaryRAT().Info()), s00.FieldInfo(s53.HandoverRestrictionListExtIEs().UnlicensedSpectrumRestriction().Info()), s00.FieldInfo(s53.HandoverRestrictionListExtIEs().CNTypeRestrictions().Info()), s00.FieldInfo(s53.HandoverRestrictionListExtIEs().NRrestrictionin5GS().Info()), s00.FieldInfo(s53.HandoverRestrictionListExtIEs().LastNGRANPLMNIdentity().Info()), s00.FieldInfo(s53.HandoverRestrictionListExtIEs().RATRestrictions().Info())}
				s30.BridgeMergeNestedValidation(report, s53.BridgeHandoverRestrictionListExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(282):
					if value, ok := fields[i].ExtensionValue.AsCNTypeRestrictions(); ok {
						s61.BridgeWalkValidationCNTypeRestrictions(value, report, fmt.Sprintf("%s[%d]{id=282}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(336):
					if value, ok := fields[i].ExtensionValue.AsRATRestrictions(); ok {
						BridgeWalkValidationRATRestrictions(value, report, fmt.Sprintf("%s[%d]{id=336}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInformationOnRecommendedCellsAndENBsForPaging(v *s42.InformationOnRecommendedCellsAndENBsForPaging, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationRecommendedCellsForPaging(&v.RecommendedCellsForPaging, report, path+".recommendedCellsForPaging", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationRecommendedENBsForPaging(&v.RecommendENBsForPaging, report, path+".recommendENBsForPaging", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s34.BridgeInformationOnRecommendedCellsAndENBsForPagingExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationInitialContextSetupFailure(v *s30.InitialContextSetupFailure, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s26.InitialContextSetupFailureIEs().MMEUES1APID().Info(), s26.InitialContextSetupFailureIEs().ENBUES1APID().Info(), s26.InitialContextSetupFailureIEs().Cause().Info(), s26.InitialContextSetupFailureIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s34.BridgeInitialContextSetupFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationInitialContextSetupResponse(v *s50.InitialContextSetupResponse, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s50.InitialContextSetupResponseIEs().MMEUES1APID().Info(), s50.InitialContextSetupResponseIEs().ENBUES1APID().Info(), s50.InitialContextSetupResponseIEs().ERABSetupListCtxtSURes().Info(), s50.InitialContextSetupResponseIEs().ERABFailedToSetupListCtxtSURes().Info(), s50.InitialContextSetupResponseIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s50.BridgeInitialContextSetupResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(51):
				if value, ok := fields[i].Value.AsERABSetupListCtxtSURes(); ok {
					s61.BridgeWalkValidationERABSetupListCtxtSURes(value, report, fmt.Sprintf("%s[%d]{id=51}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(48):
				if value, ok := fields[i].Value.AsERABFailedToSetupListCtxtSURes(); ok {
					s61.BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=48}", nestedPath, i), false)
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
func BridgeWalkValidationInterSystemMeasurementItem(v *s21.InterSystemMeasurementItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s34.BridgeInterSystemMeasurementItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationInterSystemMeasurementList(v *s21.InterSystemMeasurementList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationInterSystemMeasurementItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationInterSystemMeasurementParameters(v *s28.InterSystemMeasurementParameters, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.InterSystemMeasurementList != nil {
		BridgeWalkValidationInterSystemMeasurementList(&v.InterSystemMeasurementList, report, path+".interSystemMeasurementList", false)
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
				s30.BridgeMergeNestedValidation(report, s34.BridgeInterSystemMeasurementParametersExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationIntersystemMeasurementConfiguration(v *s28.IntersystemMeasurementConfiguration, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationInterSystemMeasurementParameters(&v.InterSystemMeasurementParameters, report, path+".interSystemMeasurementParameters", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s34.BridgeIntersystemMeasurementConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationLAI(v *s22.LAI, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s34.BridgeLAIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationLTENTNTAIInformation(v *s22.LTENTNTAIInformation, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationTACListInLTENTN(&v.TACListInLTENTN, report, path+".tACList-In-LTE-NTN", false)
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
				s30.BridgeMergeNestedValidation(report, s34.BridgeLTENTNTAIInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationLastVisitedCellItem(v *s52.LastVisitedCellItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.LastVisitedCellItemChoiceEUTRANCell && v.EUTRANCell != nil {
		BridgeWalkValidationLastVisitedEUTRANCellInformation(v.EUTRANCell, report, path+".e-UTRAN-Cell", false)
	}
	if v.Choice == s00.LastVisitedCellItemChoiceGERANCell && v.GERANCell != nil {
		BridgeWalkValidationLastVisitedGERANCellInformation(v.GERANCell, report, path+".gERAN-Cell", false)
	}
}
func BridgeWalkValidationLastVisitedEUTRANCellInformation(v *s52.LastVisitedEUTRANCellInformation, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s61.BridgeWalkValidationEUTRANCGI(&v.GlobalCellID, report, path+".global-Cell-ID", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s61.BridgeWalkValidationCellType(&v.CellType, report, path+".cellType", false)
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
				rows := []s00.FieldInfo{s00.FieldInfo(s52.LastVisitedEUTRANCellInformationExtIEs().TimeUEStayedInCellEnhancedGranularity().Info()), s00.FieldInfo(s52.LastVisitedEUTRANCellInformationExtIEs().HOCause().Info()), s00.FieldInfo(s52.LastVisitedEUTRANCellInformationExtIEs().LastVisitedPSCellList().Info())}
				s30.BridgeMergeNestedValidation(report, s52.BridgeLastVisitedEUTRANCellInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(168):
					if value, ok := fields[i].ExtensionValue.AsHOCause(); ok {
						s61.BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=168}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(329):
					if value, ok := fields[i].ExtensionValue.AsLastVisitedPSCellList(); ok {
						BridgeWalkValidationLastVisitedPSCellList(value, report, fmt.Sprintf("%s[%d]{id=329}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLastVisitedGERANCellInformation(v *s22.LastVisitedGERANCellInformation, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationLastVisitedPSCellInformation(v *s23.LastVisitedPSCellInformation, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.PSCellID != nil {
		BridgeWalkValidationPSCellInformation(v.PSCellID, report, path+".pSCellID", false)
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
				s30.BridgeMergeNestedValidation(report, s34.BridgeLastVisitedPSCellInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationLastVisitedPSCellList(v *s23.LastVisitedPSCellList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationLastVisitedPSCellInformation(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationListeningSubframePattern(v *s22.ListeningSubframePattern, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s34.BridgeListeningSubframePatternExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationLocationReport(v *s42.LocationReport, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s41.LocationReportIEs().MMEUES1APID().Info(), s41.LocationReportIEs().ENBUES1APID().Info(), s41.LocationReportIEs().EUTRANCGI().Info(), s41.LocationReportIEs().TAI().Info(), s41.LocationReportIEs().RequestType().Info(), s41.LocationReportIEs().PSCellInformation().Info(), s41.LocationReportIEs().LTENTNTAIInformation().Info()}
			s30.BridgeMergeNestedValidation(report, s42.BridgeLocationReportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
					BridgeWalkValidationTAI(value, report, fmt.Sprintf("%s[%d]{id=67}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(98):
				if value, ok := fields[i].Value.AsRequestType(); ok {
					BridgeWalkValidationRequestType(value, report, fmt.Sprintf("%s[%d]{id=98}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(288):
				if value, ok := fields[i].Value.AsPSCellInformation(); ok {
					BridgeWalkValidationPSCellInformation(value, report, fmt.Sprintf("%s[%d]{id=288}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(339):
				if value, ok := fields[i].Value.AsLTENTNTAIInformation(); ok {
					BridgeWalkValidationLTENTNTAIInformation(value, report, fmt.Sprintf("%s[%d]{id=339}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLocationReportingControl(v *s31.LocationReportingControl, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s31.LocationReportingControlIEs().MMEUES1APID().Info(), s31.LocationReportingControlIEs().ENBUES1APID().Info(), s31.LocationReportingControlIEs().RequestType().Info()}
			s30.BridgeMergeNestedValidation(report, s34.BridgeLocationReportingControlIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(98):
				if value, ok := fields[i].Value.AsRequestType(); ok {
					BridgeWalkValidationRequestType(value, report, fmt.Sprintf("%s[%d]{id=98}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLocationReportingFailureIndication(v *s30.LocationReportingFailureIndication, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s22.LocationReportingFailureIndicationIEs().MMEUES1APID().Info(), s22.LocationReportingFailureIndicationIEs().ENBUES1APID().Info(), s22.LocationReportingFailureIndicationIEs().Cause().Info()}
			s30.BridgeMergeNestedValidation(report, s34.BridgeLocationReportingFailureIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationLoggedMBSFNMDT(v *s28.LoggedMBSFNMDT, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.MBSFNResultToLog != nil {
		BridgeWalkValidationMBSFNResultToLog(&v.MBSFNResultToLog, report, path+".mBSFN-ResultToLog", false)
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
				s30.BridgeMergeNestedValidation(report, s34.BridgeLoggedMBSFNMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationLoggedMDTTrigger(v *s22.LoggedMDTTrigger, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.LoggedMDTTriggerChoiceEventTrigger && v.EventTrigger != nil {
		BridgeWalkValidationEventTrigger(v.EventTrigger, report, path+".eventTrigger", false)
	}
}
func BridgeWalkValidationM1PeriodicReporting(v *s22.M1PeriodicReporting, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s34.BridgeM1PeriodicReportingExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationM1ThresholdEventA2(v *s22.M1ThresholdEventA2, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationMeasurementThresholdA2(&v.MeasurementThreshold, report, path+".measurementThreshold", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s35.BridgeM1ThresholdEventA2ExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationM3Configuration(v *s22.M3Configuration, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s35.BridgeM3ConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationM4Configuration(v *s22.M4Configuration, report *s25.ValidationReport, path string, skipRoot bool) {
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
				rows := []s00.FieldInfo{s00.FieldInfo(s11.M4ConfigurationExtIEs().M4ReportAmount().Info())}
				s30.BridgeMergeNestedValidation(report, s35.BridgeM4ConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationM5Configuration(v *s22.M5Configuration, report *s25.ValidationReport, path string, skipRoot bool) {
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
				rows := []s00.FieldInfo{s00.FieldInfo(s11.M5ConfigurationExtIEs().M5ReportAmount().Info())}
				s30.BridgeMergeNestedValidation(report, s35.BridgeM5ConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationM6Configuration(v *s22.M6Configuration, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s11.M6ConfigurationExtIEs().M6ReportAmount().Info())}
				s30.BridgeMergeNestedValidation(report, s35.BridgeM6ConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationM7Configuration(v *s22.M7Configuration, report *s25.ValidationReport, path string, skipRoot bool) {
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
				rows := []s00.FieldInfo{s00.FieldInfo(s11.M7ConfigurationExtIEs().M7ReportAmount().Info())}
				s30.BridgeMergeNestedValidation(report, s35.BridgeM7ConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationMBSFNResultToLog(v *s22.MBSFNResultToLog, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationMBSFNResultToLogInfo(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationMBSFNResultToLogInfo(v *s22.MBSFNResultToLogInfo, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s35.BridgeMBSFNResultToLogInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationMDTModeExtension(v *s22.MDTModeExtension, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationMDTPLMNList(v *s00.MDTPLMNList, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationMMECPRelocationIndication(v *s22.MMECPRelocationIndication, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s12.MMECPRelocationIndicationIEs().MMEUES1APID().Info(), s12.MMECPRelocationIndicationIEs().ENBUES1APID().Info()}
			s30.BridgeMergeNestedValidation(report, s35.BridgeMMECPRelocationIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationMMEConfigurationUpdate(v *s54.MMEConfigurationUpdate, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s54.MMEConfigurationUpdateIEs().MMEname().Info(), s54.MMEConfigurationUpdateIEs().ServedGUMMEIs().Info(), s54.MMEConfigurationUpdateIEs().RelativeMMECapacity().Info(), s54.MMEConfigurationUpdateIEs().ServedDCNs().Info()}
			s30.BridgeMergeNestedValidation(report, s54.BridgeMMEConfigurationUpdateIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMMEConfigurationUpdateAcknowledge(v *s30.MMEConfigurationUpdateAcknowledge, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s26.MMEConfigurationUpdateAcknowledgeIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s35.BridgeMMEConfigurationUpdateAcknowledgeIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationMMEConfigurationUpdateFailure(v *s30.MMEConfigurationUpdateFailure, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s27.MMEConfigurationUpdateFailureIEs().Cause().Info(), s27.MMEConfigurationUpdateFailureIEs().TimeToWait().Info(), s27.MMEConfigurationUpdateFailureIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s35.BridgeMMEConfigurationUpdateFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationMMEEarlyStatusTransfer(v *s48.MMEEarlyStatusTransfer, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s47.MMEEarlyStatusTransferIEs().MMEUES1APID().Info(), s47.MMEEarlyStatusTransferIEs().ENBUES1APID().Info(), s47.MMEEarlyStatusTransferIEs().ENBEarlyStatusTransferTransparentContainer().Info()}
			s30.BridgeMergeNestedValidation(report, s48.BridgeMMEEarlyStatusTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(321):
				if value, ok := fields[i].Value.AsENBEarlyStatusTransferTransparentContainer(); ok {
					s61.BridgeWalkValidationENBEarlyStatusTransferTransparentContainer(value, report, fmt.Sprintf("%s[%d]{id=321}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMMEPagingTarget(v *s40.MMEPagingTarget, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.MMEPagingTargetChoiceGlobalENBID && v.GlobalENBID != nil {
		s61.BridgeWalkValidationGlobalENBID(v.GlobalENBID, report, path+".global-ENB-ID", false)
	}
	if v.Choice == s00.MMEPagingTargetChoiceTAI && v.TAI != nil {
		BridgeWalkValidationTAI(v.TAI, report, path+".tAI", false)
	}
}
func BridgeWalkValidationMMEStatusTransfer(v *s30.MMEStatusTransfer, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s25.MMEStatusTransferIEs().MMEUES1APID().Info(), s25.MMEStatusTransferIEs().ENBUES1APID().Info(), s25.MMEStatusTransferIEs().ENBStatusTransferTransparentContainer().Info()}
			s30.BridgeMergeNestedValidation(report, s35.BridgeMMEStatusTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(90):
				if value, ok := fields[i].Value.AsENBStatusTransferTransparentContainer(); ok {
					s61.BridgeWalkValidationENBStatusTransferTransparentContainer(value, report, fmt.Sprintf("%s[%d]{id=90}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMeasurementThresholdA2(v *s22.MeasurementThresholdA2, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationMeasurementThresholdL1LoggedMDT(v *s22.MeasurementThresholdL1LoggedMDT, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationMultiCellLoadReportingRequest(v *s28.MultiCellLoadReportingRequest, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationRequestedCellList(&v.RequestedCellList, report, path+".requestedCellList", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMultiCellLoadReportingResponse(v *s22.MultiCellLoadReportingResponse, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationMultiCellLoadReportingResponseItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationMultiCellLoadReportingResponseItem(v *s22.MultiCellLoadReportingResponseItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.MultiCellLoadReportingResponseItemChoiceEUTRANResponse && v.EUTRANResponse != nil {
		s61.BridgeWalkValidationEUTRANResponse(v.EUTRANResponse, report, path+".eUTRANResponse", false)
	}
	if v.Choice == s00.MultiCellLoadReportingResponseItemChoiceEHRPD && v.EHRPD != nil {
		s61.BridgeWalkValidationEHRPDMultiSectorLoadReportingResponseItem(v.EHRPD, report, path+".eHRPD", false)
	}
}
func BridgeWalkValidationMutingPatternInformation(v *s22.MutingPatternInformation, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s35.BridgeMutingPatternInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationNASDeliveryIndication(v *s22.NASDeliveryIndication, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s12.NASDeliveryIndicationIEs().MMEUES1APID().Info(), s12.NASDeliveryIndicationIEs().ENBUES1APID().Info()}
			s30.BridgeMergeNestedValidation(report, s35.BridgeNASDeliveryIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationNASNonDeliveryIndication(v *s30.NASNonDeliveryIndication, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s23.NASNonDeliveryIndicationIEs().MMEUES1APID().Info(), s23.NASNonDeliveryIndicationIEs().ENBUES1APID().Info(), s23.NASNonDeliveryIndicationIEs().NASPDU().Info(), s23.NASNonDeliveryIndicationIEs().Cause().Info()}
			s30.BridgeMergeNestedValidation(report, s35.BridgeNASNonDeliveryIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationNBIoTPagingEDRXInformation(v *s23.NBIoTPagingEDRXInformation, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s35.BridgeNBIoTPagingEDRXInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationNGENB(v *s23.NGENB, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s61.BridgeWalkValidationGlobalENBID(&v.GlobalNgENBID, report, path+".global-ng-eNB-ID", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s35.BridgeNGENBExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationNRCGI(v *s23.NRCGI, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s35.BridgeNRCGIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationNRUESecurityCapabilities(v *s23.NRUESecurityCapabilities, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s35.BridgeNRUESecurityCapabilitiesExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationNRUESidelinkAggregateMaximumBitrate(v *s23.NRUESidelinkAggregateMaximumBitrate, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s35.BridgeNRUESidelinkAggregateMaximumBitrateExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationNRV2XServicesAuthorized(v *s23.NRV2XServicesAuthorized, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s35.BridgeNRV2XServicesAuthorizedExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationNotificationCellList(v *s23.NotificationCellList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationNotificationCellListItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationNotificationCellListItem(v *s23.NotificationCellListItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationOverloadResponse(v *s23.OverloadResponse, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationOverloadStart(v *s52.OverloadStart, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s52.OverloadStartIEs().OverloadResponse().Info(), s52.OverloadStartIEs().GUMMEIList().Info(), s52.OverloadStartIEs().TrafficLoadReductionIndication().Info()}
			s30.BridgeMergeNestedValidation(report, s52.BridgeOverloadStartIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(101):
				if value, ok := fields[i].Value.AsOverloadResponse(); ok {
					BridgeWalkValidationOverloadResponse(value, report, fmt.Sprintf("%s[%d]{id=101}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(154):
				if value, ok := fields[i].Value.AsGUMMEIList(); ok {
					s61.BridgeWalkValidationGUMMEIList(value, report, fmt.Sprintf("%s[%d]{id=154}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationOverloadStop(v *s52.OverloadStop, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s52.OverloadStopIEs().GUMMEIList().Info()}
			s30.BridgeMergeNestedValidation(report, s52.BridgeOverloadStopIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(154):
				if value, ok := fields[i].Value.AsGUMMEIList(); ok {
					s61.BridgeWalkValidationGUMMEIList(value, report, fmt.Sprintf("%s[%d]{id=154}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPC5FlowBitRates(v *s23.PC5FlowBitRates, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s35.BridgePC5FlowBitRatesExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationPC5QoSFlowItem(v *s23.PC5QoSFlowItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.Pc5FlowBitRates != nil {
		BridgeWalkValidationPC5FlowBitRates(v.Pc5FlowBitRates, report, path+".pc5FlowBitRates", false)
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
				s30.BridgeMergeNestedValidation(report, s35.BridgePC5QoSFlowItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationPC5QoSFlowList(v *s23.PC5QoSFlowList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationPC5QoSFlowItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationPC5QoSParameters(v *s28.PC5QoSParameters, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationPC5QoSFlowList(&v.Pc5QoSFlowList, report, path+".pc5QoSFlowList", false)
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
				s30.BridgeMergeNestedValidation(report, s35.BridgePC5QoSParametersExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationPLMNAreaBasedQMC(v *s23.PLMNAreaBasedQMC, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationPLMNListforQMC(&v.PlmnListforQMC, report, path+".plmnListforQMC", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s35.BridgePLMNAreaBasedQMCExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationPLMNListforQMC(v *s00.PLMNListforQMC, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationPSCellInformation(v *s23.PSCellInformation, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationNRCGI(&v.NCGI, report, path+".nCGI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s35.BridgePSCellInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationPWSFailureIndication(v *s52.PWSFailureIndication, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s52.PWSFailureIndicationIEs().PWSfailedECGIList().Info(), s52.PWSFailureIndicationIEs().GlobalENBID().Info()}
			s30.BridgeMergeNestedValidation(report, s53.BridgePWSFailureIndicationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(222):
				if value, ok := fields[i].Value.AsPWSfailedECGIList(); ok {
					BridgeWalkValidationPWSfailedECGIList(value, report, fmt.Sprintf("%s[%d]{id=222}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(59):
				if value, ok := fields[i].Value.AsGlobalENBID(); ok {
					s61.BridgeWalkValidationGlobalENBID(value, report, fmt.Sprintf("%s[%d]{id=59}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPWSfailedECGIList(v *s23.PWSfailedECGIList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		s61.BridgeWalkValidationEUTRANCGI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationPagingAttemptInformation(v *s23.PagingAttemptInformation, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s35.BridgePagingAttemptInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationPagingEDRXInformation(v *s23.PagingEDRXInformation, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s35.BridgePagingEDRXInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationPathSwitchRequestFailure(v *s30.PathSwitchRequestFailure, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s27.PathSwitchRequestFailureIEs().MMEUES1APID().Info(), s27.PathSwitchRequestFailureIEs().ENBUES1APID().Info(), s27.PathSwitchRequestFailureIEs().Cause().Info(), s27.PathSwitchRequestFailureIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s35.BridgePathSwitchRequestFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationPrivateIEID(v *s23.PrivateIEID, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationPrivateMessage(v *s30.PrivateMessage, report *s25.ValidationReport, path string, skipRoot bool) {
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
}
func BridgeWalkValidationProSeAuthorized(v *s23.ProSeAuthorized, report *s25.ValidationReport, path string, skipRoot bool) {
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
				rows := []s00.FieldInfo{s00.FieldInfo(s12.ProSeAuthorizedExtIEs().ProSeUEtoNetworkRelaying().Info())}
				s30.BridgeMergeNestedValidation(report, s35.BridgeProSeAuthorizedExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationRATRestrictions(v *s23.RATRestrictions, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationRATRestrictionsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationRATRestrictionsItem(v *s23.RATRestrictionsItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s35.BridgeRATRestrictionsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationRLFReportInformation(v *s23.RLFReportInformation, report *s25.ValidationReport, path string, skipRoot bool) {
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
				rows := []s00.FieldInfo{s00.FieldInfo(s12.RLFReportInformationExtIEs().NBIoTRLFReportContainer().Info())}
				s30.BridgeMergeNestedValidation(report, s35.BridgeRLFReportInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationRecommendedCellItem(v *s30.RecommendedCellItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s61.BridgeWalkValidationEUTRANCGI(&v.EUTRANCGI, report, path+".eUTRAN-CGI", false)
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
				s30.BridgeMergeNestedValidation(report, s36.BridgeRecommendedCellsForPagingItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationRecommendedCellList(v *s30.RecommendedCellList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s30.RecommendedCellItemIEs().RecommendedCellItem().Info()}
		s30.BridgeMergeNestedValidation(report, s35.BridgeRecommendedCellItemIEValueValidateS1APIEContainer(s30.RecommendedCellItemIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s30.RecommendedCellItemIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(214):
				if value, ok := fields[i].Value.AsRecommendedCellItem(); ok {
					BridgeWalkValidationRecommendedCellItem(value, report, fmt.Sprintf("%s[%d]{id=214}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationRecommendedCellsForPaging(v *s30.RecommendedCellsForPaging, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationRecommendedCellList(&v.RecommendedCellList, report, path+".recommendedCellList", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s36.BridgeRecommendedCellsForPagingExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationRecommendedENBItem(v *s40.RecommendedENBItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationMMEPagingTarget(&v.MMEPagingTarget, report, path+".mMEPagingTarget", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s36.BridgeRecommendedENBItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationRecommendedENBList(v *s40.RecommendedENBList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s40.RecommendedENBItemIEs().RecommendedENBItem().Info()}
		s30.BridgeMergeNestedValidation(report, s42.BridgeRecommendedENBItemIEValueValidateS1APIEContainer(s40.RecommendedENBItemIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s40.RecommendedENBItemIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
func BridgeWalkValidationRecommendedENBsForPaging(v *s42.RecommendedENBsForPaging, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationRecommendedENBList(&v.RecommendedENBList, report, path+".recommendedENBList", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s36.BridgeRecommendedENBsForPagingExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationReportingCellList(v *s23.ReportingCellList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationReportingCellListItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationReportingCellListItem(v *s23.ReportingCellListItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	s61.BridgeWalkValidationIRATCellID(&v.CellID, report, path+".cell-ID", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRequestType(v *s31.RequestType, report *s25.ValidationReport, path string, skipRoot bool) {
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
				rows := []s00.FieldInfo{s00.FieldInfo(s12.RequestTypeExtIEs().RequestTypeAdditionalInfo().Info())}
				s30.BridgeMergeNestedValidation(report, s36.BridgeRequestTypeExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationRequestedCellList(v *s23.RequestedCellList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		s61.BridgeWalkValidationIRATCellID(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationRequestedTNLInfo(v *s31.RequestedTNLInfo, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s36.BridgeRequestedTNLInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationRerouteNASRequest(v *s31.RerouteNASRequest, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s24.RerouteNASRequestIEs().ENBUES1APID().Info(), s24.RerouteNASRequestIEs().MMEUES1APID().Info(), s24.RerouteNASRequestIEs().S1Message().Info(), s24.RerouteNASRequestIEs().MMEGroupID().Info(), s24.RerouteNASRequestIEs().AdditionalGUTI().Info(), s24.RerouteNASRequestIEs().UEUsageType().Info()}
			s30.BridgeMergeNestedValidation(report, s36.BridgeRerouteNASRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(224):
				if value, ok := fields[i].Value.AsAdditionalGUTI(); ok {
					s61.BridgeWalkValidationAdditionalGUTI(value, report, fmt.Sprintf("%s[%d]{id=224}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRetrieveUEInformation(v *s36.RetrieveUEInformation, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s36.RetrieveUEInformationIEs().STMSI().Info()}
			s30.BridgeMergeNestedValidation(report, s36.BridgeRetrieveUEInformationIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(96):
				if value, ok := fields[i].Value.AsSTMSI(); ok {
					BridgeWalkValidationSTMSI(value, report, fmt.Sprintf("%s[%d]{id=96}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationS1RemovalFailure(v *s31.S1RemovalFailure, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s27.S1RemovalFailureIEs().Cause().Info(), s27.S1RemovalFailureIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s36.BridgeS1RemovalFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationS1RemovalRequest(v *s31.S1RemovalRequest, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s24.S1RemovalRequestIEs().GlobalENBID().Info()}
			s30.BridgeMergeNestedValidation(report, s36.BridgeS1RemovalRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(59):
				if value, ok := fields[i].Value.AsGlobalENBID(); ok {
					s61.BridgeWalkValidationGlobalENBID(value, report, fmt.Sprintf("%s[%d]{id=59}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationS1RemovalResponse(v *s31.S1RemovalResponse, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s27.S1RemovalResponseIEs().MMEname().Info(), s27.S1RemovalResponseIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s36.BridgeS1RemovalResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationS1SetupFailure(v *s31.S1SetupFailure, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s27.S1SetupFailureIEs().Cause().Info(), s27.S1SetupFailureIEs().TimeToWait().Info(), s27.S1SetupFailureIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s36.BridgeS1SetupFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationS1SetupRequest(v *s54.S1SetupRequest, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s54.S1SetupRequestIEs().GlobalENBID().Info(), s54.S1SetupRequestIEs().ENBname().Info(), s54.S1SetupRequestIEs().SupportedTAs().Info(), s54.S1SetupRequestIEs().DefaultPagingDRX().Info(), s54.S1SetupRequestIEs().CSGIdList().Info(), s54.S1SetupRequestIEs().UERetentionInformation().Info(), s54.S1SetupRequestIEs().NBIoTDefaultPagingDRX().Info(), s54.S1SetupRequestIEs().ConnectedengNBList().Info()}
			s30.BridgeMergeNestedValidation(report, s54.BridgeS1SetupRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(59):
				if value, ok := fields[i].Value.AsGlobalENBID(); ok {
					s61.BridgeWalkValidationGlobalENBID(value, report, fmt.Sprintf("%s[%d]{id=59}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(64):
				if value, ok := fields[i].Value.AsSupportedTAs(); ok {
					BridgeWalkValidationSupportedTAs(value, report, fmt.Sprintf("%s[%d]{id=64}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(128):
				if value, ok := fields[i].Value.AsCSGIdList(); ok {
					s61.BridgeWalkValidationCSGIdList(value, report, fmt.Sprintf("%s[%d]{id=128}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(291):
				if value, ok := fields[i].Value.AsConnectedengNBList(); ok {
					BridgeWalkValidationConnectedengNBList(value, report, fmt.Sprintf("%s[%d]{id=291}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationS1SetupResponse(v *s54.S1SetupResponse, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s54.S1SetupResponseIEs().MMEname().Info(), s54.S1SetupResponseIEs().ServedGUMMEIs().Info(), s54.S1SetupResponseIEs().RelativeMMECapacity().Info(), s54.S1SetupResponseIEs().MMERelaySupportIndicator().Info(), s54.S1SetupResponseIEs().CriticalityDiagnostics().Info(), s54.S1SetupResponseIEs().UERetentionInformation().Info(), s54.S1SetupResponseIEs().ServedDCNs().Info(), s54.S1SetupResponseIEs().IABSupported().Info()}
			s30.BridgeMergeNestedValidation(report, s54.BridgeS1SetupResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(105):
				if value, ok := fields[i].Value.AsServedGUMMEIs(); ok {
					BridgeWalkValidationServedGUMMEIs(value, report, fmt.Sprintf("%s[%d]{id=105}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s61.BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(247):
				if value, ok := fields[i].Value.AsServedDCNs(); ok {
					BridgeWalkValidationServedDCNs(value, report, fmt.Sprintf("%s[%d]{id=247}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSONInformationExtension(v *s24.SONInformationExtension, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationSONInformationReport(v *s24.SONInformationReport, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.SONInformationReportChoiceRLFReportInformation && v.RLFReportInformation != nil {
		BridgeWalkValidationRLFReportInformation(v.RLFReportInformation, report, path+".rLFReportInformation", false)
	}
}
func BridgeWalkValidationSONtransferCause(v *s24.SONtransferCause, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationSONtransferResponseContainer(v *s28.SONtransferResponseContainer, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.SONtransferResponseContainerChoiceCellLoadReporting && v.CellLoadReporting != nil {
		s61.BridgeWalkValidationCellLoadReportingResponse(v.CellLoadReporting, report, path+".cellLoadReporting", false)
	}
	if v.Choice == s00.SONtransferResponseContainerChoiceMultiCellLoadReporting && v.MultiCellLoadReporting != nil {
		BridgeWalkValidationMultiCellLoadReportingResponse(&v.MultiCellLoadReporting, report, path+".multiCellLoadReporting", false)
	}
	if v.Choice == s00.SONtransferResponseContainerChoiceEventTriggeredCellLoadReporting && v.EventTriggeredCellLoadReporting != nil {
		s61.BridgeWalkValidationEventTriggeredCellLoadReportingResponse(v.EventTriggeredCellLoadReporting, report, path+".eventTriggeredCellLoadReporting", false)
	}
	if v.Choice == s00.SONtransferResponseContainerChoiceEutranCellActivation && v.EutranCellActivation != nil {
		s61.BridgeWalkValidationCellActivationResponse(v.EutranCellActivation, report, path+".eutranCellActivation", false)
	}
}
func BridgeWalkValidationSTMSI(v *s36.STMSI, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s36.BridgeSTMSIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationScheduledCommunicationTime(v *s36.ScheduledCommunicationTime, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s36.BridgeScheduledCommunicationTimeExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationSecondaryRATDataUsageReportItem(v *s36.SecondaryRATDataUsageReportItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	s61.BridgeWalkValidationERABUsageReportList(&v.ERABUsageReportList, report, path+".e-RABUsageReportList", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s36.BridgeSecondaryRATDataUsageReportItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationSecondaryRATDataUsageReportList(v *s36.SecondaryRATDataUsageReportList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s36.SecondaryRATDataUsageReportItemIEs().SecondaryRATDataUsageReportItem().Info()}
		s30.BridgeMergeNestedValidation(report, s36.BridgeSecondaryRATDataUsageReportItemIEValueValidateS1APIEContainer(s36.SecondaryRATDataUsageReportItemIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s36.SecondaryRATDataUsageReportItemIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(265):
				if value, ok := fields[i].Value.AsSecondaryRATDataUsageReportItem(); ok {
					BridgeWalkValidationSecondaryRATDataUsageReportItem(value, report, fmt.Sprintf("%s[%d]{id=265}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationSecurityContext(v *s36.SecurityContext, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s37.BridgeSecurityContextExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationSecurityIndication(v *s37.SecurityIndication, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s38.BridgeSecurityIndicationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationSecurityResult(v *s38.SecurityResult, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s39.BridgeSecurityResultExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationSensorMeasConfigNameItem(v *s39.SensorMeasConfigNameItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationSensorNameConfig(&v.SensorNameConfig, report, path+".sensorNameConfig", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s39.BridgeSensorMeasConfigNameItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationSensorMeasConfigNameList(v *s39.SensorMeasConfigNameList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationSensorMeasConfigNameItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationSensorMeasurementConfiguration(v *s39.SensorMeasurementConfiguration, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.SensorMeasConfigNameList != nil {
		BridgeWalkValidationSensorMeasConfigNameList(&v.SensorMeasConfigNameList, report, path+".sensorMeasConfigNameList", false)
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
				s30.BridgeMergeNestedValidation(report, s39.BridgeSensorMeasurementConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationSensorNameConfig(v *s39.SensorNameConfig, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationServedDCNs(v *s39.ServedDCNs, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationServedDCNsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationServedDCNsItem(v *s39.ServedDCNsItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s39.BridgeServedDCNsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationServedGUMMEIs(v *s39.ServedGUMMEIs, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationServedGUMMEIsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationServedGUMMEIsItem(v *s39.ServedGUMMEIsItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationServedPLMNs(&v.ServedPLMNs, report, path+".servedPLMNs", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationServedGroupIDs(&v.ServedGroupIDs, report, path+".servedGroupIDs", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationServedMMECs(&v.ServedMMECs, report, path+".servedMMECs", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s13.ServedGUMMEIsItemExtIEs().GUMMEIType().Info())}
				s30.BridgeMergeNestedValidation(report, s39.BridgeServedGUMMEIsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationServedGroupIDs(v *s00.ServedGroupIDs, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationServedMMECs(v *s00.ServedMMECs, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationServedPLMNs(v *s00.ServedPLMNs, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationSourceNgRanNodeID(v *s39.SourceNgRanNodeID, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationGlobalRANNODEID(&v.GlobalRANNODEID, report, path+".global-RAN-NODE-ID", false)
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
				s30.BridgeMergeNestedValidation(report, s39.BridgeSourceNgRanNodeIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationSourceNodeID(v *s39.SourceNodeID, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
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
func BridgeWalkValidationSourceNodeIDExtension(v *s24.SourceNodeIDExtension, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationSourceeNBID(v *s41.SourceeNBID, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationTAI(&v.SelectedTAI, report, path+".selected-TAI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s39.BridgeSourceeNBIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(v *s39.SubscriptionBasedUEDifferentiationInfo, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.ScheduledCommunicationTime != nil {
		BridgeWalkValidationScheduledCommunicationTime(v.ScheduledCommunicationTime, report, path+".scheduledCommunicationTime", false)
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
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s40.BridgeSubscriptionBasedUEDifferentiationInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationSupportedTAs(v *s40.SupportedTAs, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationSupportedTAsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationSupportedTAsItem(v *s40.SupportedTAsItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	s61.BridgeWalkValidationBPLMNs(&v.BroadcastPLMNs, report, path+".broadcastPLMNs", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s13.SupportedTAsItemExtIEs().RATType().Info())}
				s30.BridgeMergeNestedValidation(report, s40.BridgeSupportedTAsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationSynchronisationInformation(v *s40.SynchronisationInformation, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.ListeningSubframePattern != nil {
		BridgeWalkValidationListeningSubframePattern(v.ListeningSubframePattern, report, path+".listeningSubframePattern", false)
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.AggressoreCGIList != nil {
		s61.BridgeWalkValidationIEsECGIList(&v.AggressoreCGIList, report, path+".aggressoreCGI-List", false)
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
				s30.BridgeMergeNestedValidation(report, s40.BridgeSynchronisationInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationTACListInLTENTN(v *s00.TACListInLTENTN, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationTAI(v *s40.TAI, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s42.BridgeTAIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationTAIBroadcast(v *s41.TAIBroadcast, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationTAIBroadcastItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationTAIBroadcastItem(v *s41.TAIBroadcastItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationTAI(&v.TAI, report, path+".tAI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	s61.BridgeWalkValidationCompletedCellinTAI(&v.CompletedCellinTAI, report, path+".completedCellinTAI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s40.BridgeTAIBroadcastItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
