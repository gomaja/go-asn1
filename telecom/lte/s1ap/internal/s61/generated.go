// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s61 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s61

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s10 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s10"
	s11 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s11"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s32 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s32"
	s33 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s33"
	s34 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s34"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s47 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s47"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s55 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s55"
	s58 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s58"
	s59 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s59"
	s60 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s60"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func NewHandoverCommand(fields s50.HandoverCommandIEContainer, options ...aper.BuildOption) (s50.HandoverCommand, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s50.HandoverCommand{}, aper.OperationError(err, "HandoverCommand")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s50.HandoverCommandIEField](bb, uint64(len(fields))); err != nil {
		return s50.HandoverCommand{}, aper.OperationError(err, "HandoverCommand")
	}
	v := s50.HandoverCommand{ProtocolIEs: make(s50.HandoverCommandIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverCommandBudget(&v, budget)
	if err != nil {
		return s50.HandoverCommand{}, aper.OperationError(err, "HandoverCommand")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s50.HandoverCommand{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "HandoverCommand")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s50.HandoverCommand{}, aper.OperationError(&s25.BuildError{Issues: issues}, "HandoverCommand")
	}
	if _, err := s50.BridgeHandoverCommandMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s50.HandoverCommand{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverCommand.protocolIEs:", err), "HandoverCommand")
	}
	return v, aper.OperationError(nil, "HandoverCommand")
}
func NewHandoverPreparationFailure(fields s26.HandoverPreparationFailureIEContainer, options ...aper.BuildOption) (s29.HandoverPreparationFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s29.HandoverPreparationFailure{}, aper.OperationError(err, "HandoverPreparationFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s26.HandoverPreparationFailureIEField](bb, uint64(len(fields))); err != nil {
		return s29.HandoverPreparationFailure{}, aper.OperationError(err, "HandoverPreparationFailure")
	}
	v := s29.HandoverPreparationFailure{ProtocolIEs: make(s26.HandoverPreparationFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverPreparationFailureBudget(&v, budget)
	if err != nil {
		return s29.HandoverPreparationFailure{}, aper.OperationError(err, "HandoverPreparationFailure")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s29.HandoverPreparationFailure{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "HandoverPreparationFailure")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s29.HandoverPreparationFailure{}, aper.OperationError(&s25.BuildError{Issues: issues}, "HandoverPreparationFailure")
	}
	if _, err := s29.BridgeHandoverPreparationFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s29.HandoverPreparationFailure{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverPreparationFailure.protocolIEs:", err), "HandoverPreparationFailure")
	}
	return v, aper.OperationError(nil, "HandoverPreparationFailure")
}
func NewHandoverRequestAcknowledge(fields s49.HandoverRequestAcknowledgeIEContainer, options ...aper.BuildOption) (s49.HandoverRequestAcknowledge, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s49.HandoverRequestAcknowledge{}, aper.OperationError(err, "HandoverRequestAcknowledge")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s49.HandoverRequestAcknowledgeIEField](bb, uint64(len(fields))); err != nil {
		return s49.HandoverRequestAcknowledge{}, aper.OperationError(err, "HandoverRequestAcknowledge")
	}
	v := s49.HandoverRequestAcknowledge{ProtocolIEs: make(s49.HandoverRequestAcknowledgeIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverRequestAcknowledgeBudget(&v, budget)
	if err != nil {
		return s49.HandoverRequestAcknowledge{}, aper.OperationError(err, "HandoverRequestAcknowledge")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s49.HandoverRequestAcknowledge{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "HandoverRequestAcknowledge")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s49.HandoverRequestAcknowledge{}, aper.OperationError(&s25.BuildError{Issues: issues}, "HandoverRequestAcknowledge")
	}
	if _, err := s49.BridgeHandoverRequestAcknowledgeMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s49.HandoverRequestAcknowledge{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverRequestAcknowledge.protocolIEs:", err), "HandoverRequestAcknowledge")
	}
	return v, aper.OperationError(nil, "HandoverRequestAcknowledge")
}
func NewHandoverFailure(fields s26.HandoverFailureIEContainer, options ...aper.BuildOption) (s29.HandoverFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s29.HandoverFailure{}, aper.OperationError(err, "HandoverFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s26.HandoverFailureIEField](bb, uint64(len(fields))); err != nil {
		return s29.HandoverFailure{}, aper.OperationError(err, "HandoverFailure")
	}
	v := s29.HandoverFailure{ProtocolIEs: make(s26.HandoverFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverFailureBudget(&v, budget)
	if err != nil {
		return s29.HandoverFailure{}, aper.OperationError(err, "HandoverFailure")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s29.HandoverFailure{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "HandoverFailure")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s29.HandoverFailure{}, aper.OperationError(&s25.BuildError{Issues: issues}, "HandoverFailure")
	}
	if _, err := s29.BridgeHandoverFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s29.HandoverFailure{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverFailure.protocolIEs:", err), "HandoverFailure")
	}
	return v, aper.OperationError(nil, "HandoverFailure")
}
func NewHandoverCancel(fields s21.HandoverCancelIEContainer, options ...aper.BuildOption) (s29.HandoverCancel, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s29.HandoverCancel{}, aper.OperationError(err, "HandoverCancel")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s21.HandoverCancelIEField](bb, uint64(len(fields))); err != nil {
		return s29.HandoverCancel{}, aper.OperationError(err, "HandoverCancel")
	}
	v := s29.HandoverCancel{ProtocolIEs: make(s21.HandoverCancelIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverCancelBudget(&v, budget)
	if err != nil {
		return s29.HandoverCancel{}, aper.OperationError(err, "HandoverCancel")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s29.HandoverCancel{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "HandoverCancel")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s29.HandoverCancel{}, aper.OperationError(&s25.BuildError{Issues: issues}, "HandoverCancel")
	}
	if _, err := s29.BridgeHandoverCancelMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s29.HandoverCancel{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverCancel.protocolIEs:", err), "HandoverCancel")
	}
	return v, aper.OperationError(nil, "HandoverCancel")
}
func NewHandoverCancelAcknowledge(fields s26.HandoverCancelAcknowledgeIEContainer, options ...aper.BuildOption) (s29.HandoverCancelAcknowledge, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s29.HandoverCancelAcknowledge{}, aper.OperationError(err, "HandoverCancelAcknowledge")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s26.HandoverCancelAcknowledgeIEField](bb, uint64(len(fields))); err != nil {
		return s29.HandoverCancelAcknowledge{}, aper.OperationError(err, "HandoverCancelAcknowledge")
	}
	v := s29.HandoverCancelAcknowledge{ProtocolIEs: make(s26.HandoverCancelAcknowledgeIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverCancelAcknowledgeBudget(&v, budget)
	if err != nil {
		return s29.HandoverCancelAcknowledge{}, aper.OperationError(err, "HandoverCancelAcknowledge")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s29.HandoverCancelAcknowledge{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "HandoverCancelAcknowledge")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s29.HandoverCancelAcknowledge{}, aper.OperationError(&s25.BuildError{Issues: issues}, "HandoverCancelAcknowledge")
	}
	if _, err := s29.BridgeHandoverCancelAcknowledgeMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s29.HandoverCancelAcknowledge{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverCancelAcknowledge.protocolIEs:", err), "HandoverCancelAcknowledge")
	}
	return v, aper.OperationError(nil, "HandoverCancelAcknowledge")
}
func NewDownlinkS1cdma2000tunnelling(fields s50.DownlinkS1cdma2000tunnellingIEContainer, options ...aper.BuildOption) (s50.DownlinkS1cdma2000tunnelling, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s50.DownlinkS1cdma2000tunnelling{}, aper.OperationError(err, "DownlinkS1cdma2000tunnelling")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s50.DownlinkS1cdma2000tunnellingIEField](bb, uint64(len(fields))); err != nil {
		return s50.DownlinkS1cdma2000tunnelling{}, aper.OperationError(err, "DownlinkS1cdma2000tunnelling")
	}
	v := s50.DownlinkS1cdma2000tunnelling{ProtocolIEs: make(s50.DownlinkS1cdma2000tunnellingIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateDownlinkS1cdma2000tunnellingBudget(&v, budget)
	if err != nil {
		return s50.DownlinkS1cdma2000tunnelling{}, aper.OperationError(err, "DownlinkS1cdma2000tunnelling")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s50.DownlinkS1cdma2000tunnelling{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "DownlinkS1cdma2000tunnelling")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s50.DownlinkS1cdma2000tunnelling{}, aper.OperationError(&s25.BuildError{Issues: issues}, "DownlinkS1cdma2000tunnelling")
	}
	if _, err := s50.BridgeDownlinkS1cdma2000tunnellingMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s50.DownlinkS1cdma2000tunnelling{}, aper.OperationError(fmt.Errorf("%s %w", "DownlinkS1cdma2000tunnelling.protocolIEs:", err), "DownlinkS1cdma2000tunnelling")
	}
	return v, aper.OperationError(nil, "DownlinkS1cdma2000tunnelling")
}
func NewENBStatusTransfer(fields s25.ENBStatusTransferIEContainer, options ...aper.BuildOption) (s28.ENBStatusTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.ENBStatusTransfer{}, aper.OperationError(err, "ENBStatusTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s25.ENBStatusTransferIEField](bb, uint64(len(fields))); err != nil {
		return s28.ENBStatusTransfer{}, aper.OperationError(err, "ENBStatusTransfer")
	}
	v := s28.ENBStatusTransfer{ProtocolIEs: make(s25.ENBStatusTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBStatusTransferBudget(&v, budget)
	if err != nil {
		return s28.ENBStatusTransfer{}, aper.OperationError(err, "ENBStatusTransfer")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s28.ENBStatusTransfer{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ENBStatusTransfer")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s28.ENBStatusTransfer{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ENBStatusTransfer")
	}
	if _, err := s28.BridgeENBStatusTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s28.ENBStatusTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "ENBStatusTransfer.protocolIEs:", err), "ENBStatusTransfer")
	}
	return v, aper.OperationError(nil, "ENBStatusTransfer")
}
func NewDeactivateTrace(fields s09.DeactivateTraceIEContainer, options ...aper.BuildOption) (s18.DeactivateTrace, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.DeactivateTrace{}, aper.OperationError(err, "DeactivateTrace")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s09.DeactivateTraceIEField](bb, uint64(len(fields))); err != nil {
		return s18.DeactivateTrace{}, aper.OperationError(err, "DeactivateTrace")
	}
	v := s18.DeactivateTrace{ProtocolIEs: make(s09.DeactivateTraceIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateDeactivateTraceBudget(&v, budget)
	if err != nil {
		return s18.DeactivateTrace{}, aper.OperationError(err, "DeactivateTrace")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s18.DeactivateTrace{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "DeactivateTrace")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s18.DeactivateTrace{}, aper.OperationError(&s25.BuildError{Issues: issues}, "DeactivateTrace")
	}
	if _, err := s18.BridgeDeactivateTraceMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s18.DeactivateTrace{}, aper.OperationError(fmt.Errorf("%s %w", "DeactivateTrace.protocolIEs:", err), "DeactivateTrace")
	}
	return v, aper.OperationError(nil, "DeactivateTrace")
}
func NewENBConfigurationUpdateAcknowledge(fields s26.ENBConfigurationUpdateAcknowledgeIEContainer, options ...aper.BuildOption) (s28.ENBConfigurationUpdateAcknowledge, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.ENBConfigurationUpdateAcknowledge{}, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s26.ENBConfigurationUpdateAcknowledgeIEField](bb, uint64(len(fields))); err != nil {
		return s28.ENBConfigurationUpdateAcknowledge{}, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
	}
	v := s28.ENBConfigurationUpdateAcknowledge{ProtocolIEs: make(s26.ENBConfigurationUpdateAcknowledgeIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBConfigurationUpdateAcknowledgeBudget(&v, budget)
	if err != nil {
		return s28.ENBConfigurationUpdateAcknowledge{}, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s28.ENBConfigurationUpdateAcknowledge{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ENBConfigurationUpdateAcknowledge")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s28.ENBConfigurationUpdateAcknowledge{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ENBConfigurationUpdateAcknowledge")
	}
	if _, err := s28.BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s28.ENBConfigurationUpdateAcknowledge{}, aper.OperationError(fmt.Errorf("%s %w", "ENBConfigurationUpdateAcknowledge.protocolIEs:", err), "ENBConfigurationUpdateAcknowledge")
	}
	return v, aper.OperationError(nil, "ENBConfigurationUpdateAcknowledge")
}
func NewENBConfigurationUpdateFailure(fields s26.ENBConfigurationUpdateFailureIEContainer, options ...aper.BuildOption) (s28.ENBConfigurationUpdateFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s28.ENBConfigurationUpdateFailure{}, aper.OperationError(err, "ENBConfigurationUpdateFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s26.ENBConfigurationUpdateFailureIEField](bb, uint64(len(fields))); err != nil {
		return s28.ENBConfigurationUpdateFailure{}, aper.OperationError(err, "ENBConfigurationUpdateFailure")
	}
	v := s28.ENBConfigurationUpdateFailure{ProtocolIEs: make(s26.ENBConfigurationUpdateFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBConfigurationUpdateFailureBudget(&v, budget)
	if err != nil {
		return s28.ENBConfigurationUpdateFailure{}, aper.OperationError(err, "ENBConfigurationUpdateFailure")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s28.ENBConfigurationUpdateFailure{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ENBConfigurationUpdateFailure")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s28.ENBConfigurationUpdateFailure{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ENBConfigurationUpdateFailure")
	}
	if _, err := s28.BridgeENBConfigurationUpdateFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s28.ENBConfigurationUpdateFailure{}, aper.OperationError(fmt.Errorf("%s %w", "ENBConfigurationUpdateFailure.protocolIEs:", err), "ENBConfigurationUpdateFailure")
	}
	return v, aper.OperationError(nil, "ENBConfigurationUpdateFailure")
}
func NewCellTrafficTrace(fields s20.CellTrafficTraceIEContainer, options ...aper.BuildOption) (s25.CellTrafficTrace, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s25.CellTrafficTrace{}, aper.OperationError(err, "CellTrafficTrace")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s20.CellTrafficTraceIEField](bb, uint64(len(fields))); err != nil {
		return s25.CellTrafficTrace{}, aper.OperationError(err, "CellTrafficTrace")
	}
	v := s25.CellTrafficTrace{ProtocolIEs: make(s20.CellTrafficTraceIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateCellTrafficTraceBudget(&v, budget)
	if err != nil {
		return s25.CellTrafficTrace{}, aper.OperationError(err, "CellTrafficTrace")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s25.CellTrafficTrace{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "CellTrafficTrace")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s25.CellTrafficTrace{}, aper.OperationError(&s25.BuildError{Issues: issues}, "CellTrafficTrace")
	}
	if _, err := s25.BridgeCellTrafficTraceMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s25.CellTrafficTrace{}, aper.OperationError(fmt.Errorf("%s %w", "CellTrafficTrace.protocolIEs:", err), "CellTrafficTrace")
	}
	return v, aper.OperationError(nil, "CellTrafficTrace")
}
func NewDownlinkUEAssociatedLPPaTransport(fields s09.DownlinkUEAssociatedLPPaTransportIEContainer, options ...aper.BuildOption) (s18.DownlinkUEAssociatedLPPaTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.DownlinkUEAssociatedLPPaTransport{}, aper.OperationError(err, "DownlinkUEAssociatedLPPaTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s09.DownlinkUEAssociatedLPPaTransportIEField](bb, uint64(len(fields))); err != nil {
		return s18.DownlinkUEAssociatedLPPaTransport{}, aper.OperationError(err, "DownlinkUEAssociatedLPPaTransport")
	}
	v := s18.DownlinkUEAssociatedLPPaTransport{ProtocolIEs: make(s09.DownlinkUEAssociatedLPPaTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateDownlinkUEAssociatedLPPaTransportBudget(&v, budget)
	if err != nil {
		return s18.DownlinkUEAssociatedLPPaTransport{}, aper.OperationError(err, "DownlinkUEAssociatedLPPaTransport")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s18.DownlinkUEAssociatedLPPaTransport{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "DownlinkUEAssociatedLPPaTransport")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s18.DownlinkUEAssociatedLPPaTransport{}, aper.OperationError(&s25.BuildError{Issues: issues}, "DownlinkUEAssociatedLPPaTransport")
	}
	if _, err := s18.BridgeDownlinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s18.DownlinkUEAssociatedLPPaTransport{}, aper.OperationError(fmt.Errorf("%s %w", "DownlinkUEAssociatedLPPaTransport.protocolIEs:", err), "DownlinkUEAssociatedLPPaTransport")
	}
	return v, aper.OperationError(nil, "DownlinkUEAssociatedLPPaTransport")
}
func NewDownlinkNonUEAssociatedLPPaTransport(fields s09.DownlinkNonUEAssociatedLPPaTransportIEContainer, options ...aper.BuildOption) (s18.DownlinkNonUEAssociatedLPPaTransport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.DownlinkNonUEAssociatedLPPaTransport{}, aper.OperationError(err, "DownlinkNonUEAssociatedLPPaTransport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s09.DownlinkNonUEAssociatedLPPaTransportIEField](bb, uint64(len(fields))); err != nil {
		return s18.DownlinkNonUEAssociatedLPPaTransport{}, aper.OperationError(err, "DownlinkNonUEAssociatedLPPaTransport")
	}
	v := s18.DownlinkNonUEAssociatedLPPaTransport{ProtocolIEs: make(s09.DownlinkNonUEAssociatedLPPaTransportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateDownlinkNonUEAssociatedLPPaTransportBudget(&v, budget)
	if err != nil {
		return s18.DownlinkNonUEAssociatedLPPaTransport{}, aper.OperationError(err, "DownlinkNonUEAssociatedLPPaTransport")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s18.DownlinkNonUEAssociatedLPPaTransport{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "DownlinkNonUEAssociatedLPPaTransport")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s18.DownlinkNonUEAssociatedLPPaTransport{}, aper.OperationError(&s25.BuildError{Issues: issues}, "DownlinkNonUEAssociatedLPPaTransport")
	}
	if _, err := s18.BridgeDownlinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s18.DownlinkNonUEAssociatedLPPaTransport{}, aper.OperationError(fmt.Errorf("%s %w", "DownlinkNonUEAssociatedLPPaTransport.protocolIEs:", err), "DownlinkNonUEAssociatedLPPaTransport")
	}
	return v, aper.OperationError(nil, "DownlinkNonUEAssociatedLPPaTransport")
}
func NewERABModificationConfirm(fields s49.ERABModificationConfirmIEContainer, options ...aper.BuildOption) (s49.ERABModificationConfirm, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s49.ERABModificationConfirm{}, aper.OperationError(err, "ERABModificationConfirm")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s49.ERABModificationConfirmIEField](bb, uint64(len(fields))); err != nil {
		return s49.ERABModificationConfirm{}, aper.OperationError(err, "ERABModificationConfirm")
	}
	v := s49.ERABModificationConfirm{ProtocolIEs: make(s49.ERABModificationConfirmIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateERABModificationConfirmBudget(&v, budget)
	if err != nil {
		return s49.ERABModificationConfirm{}, aper.OperationError(err, "ERABModificationConfirm")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s49.ERABModificationConfirm{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ERABModificationConfirm")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s49.ERABModificationConfirm{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ERABModificationConfirm")
	}
	if _, err := s49.BridgeERABModificationConfirmMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s49.ERABModificationConfirm{}, aper.OperationError(fmt.Errorf("%s %w", "ERABModificationConfirm.protocolIEs:", err), "ERABModificationConfirm")
	}
	return v, aper.OperationError(nil, "ERABModificationConfirm")
}
func NewHandoverSuccess(fields s11.HandoverSuccessIEContainer, options ...aper.BuildOption) (s21.HandoverSuccess, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s21.HandoverSuccess{}, aper.OperationError(err, "HandoverSuccess")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.HandoverSuccessIEField](bb, uint64(len(fields))); err != nil {
		return s21.HandoverSuccess{}, aper.OperationError(err, "HandoverSuccess")
	}
	v := s21.HandoverSuccess{ProtocolIEs: make(s11.HandoverSuccessIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverSuccessBudget(&v, budget)
	if err != nil {
		return s21.HandoverSuccess{}, aper.OperationError(err, "HandoverSuccess")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s21.HandoverSuccess{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "HandoverSuccess")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s21.HandoverSuccess{}, aper.OperationError(&s25.BuildError{Issues: issues}, "HandoverSuccess")
	}
	if _, err := s21.BridgeHandoverSuccessMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s21.HandoverSuccess{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverSuccess.protocolIEs:", err), "HandoverSuccess")
	}
	return v, aper.OperationError(nil, "HandoverSuccess")
}
func NewENBEarlyStatusTransfer(fields s47.ENBEarlyStatusTransferIEContainer, options ...aper.BuildOption) (s47.ENBEarlyStatusTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s47.ENBEarlyStatusTransfer{}, aper.OperationError(err, "ENBEarlyStatusTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s47.ENBEarlyStatusTransferIEField](bb, uint64(len(fields))); err != nil {
		return s47.ENBEarlyStatusTransfer{}, aper.OperationError(err, "ENBEarlyStatusTransfer")
	}
	v := s47.ENBEarlyStatusTransfer{ProtocolIEs: make(s47.ENBEarlyStatusTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateENBEarlyStatusTransferBudget(&v, budget)
	if err != nil {
		return s47.ENBEarlyStatusTransfer{}, aper.OperationError(err, "ENBEarlyStatusTransfer")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s47.ENBEarlyStatusTransfer{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "ENBEarlyStatusTransfer")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s47.ENBEarlyStatusTransfer{}, aper.OperationError(&s25.BuildError{Issues: issues}, "ENBEarlyStatusTransfer")
	}
	if _, err := s47.BridgeENBEarlyStatusTransferMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s47.ENBEarlyStatusTransfer{}, aper.OperationError(fmt.Errorf("%s %w", "ENBEarlyStatusTransfer.protocolIEs:", err), "ENBEarlyStatusTransfer")
	}
	return v, aper.OperationError(nil, "ENBEarlyStatusTransfer")
}

// PagingIEContainer is ProtocolIE-Container {{PagingIEs}} of TS 36.413: a list of PagingIEField values.
type PagingIEContainer []PagingIEField

// PagingIEField is ProtocolIE-Field {{PagingIEs}} of TS 36.413: an information element field.
type PagingIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         PagingIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingIEField) WithoutReplay() PagingIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *PagingIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *PagingIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *PagingIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PagingIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero PagingIEValue

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
func BridgePagingIEValueCaptureS1APProtocolIEContainer(v *PagingIEContainer, s *aper.SemanticCapture) {
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
			BridgePagingIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePagingIEValueCompareS1APProtocolIEContainer(v *PagingIEContainer, s *aper.SemanticComparison) {
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
			BridgePagingIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTraceStartIEValueCaptureS1APProtocolIEContainer(v *s60.TraceStartIEContainer, s *aper.SemanticCapture) {
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
			BridgeTraceStartIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTraceStartIEValueCompareS1APProtocolIEContainer(v *s60.TraceStartIEContainer, s *aper.SemanticComparison) {
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
			BridgeTraceStartIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeWUSAssistanceInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s15.WUSAssistanceInformationExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeWUSAssistanceInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeWUSAssistanceInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s15.WUSAssistanceInformationExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeWUSAssistanceInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PagingUEIdentityIndexValueIEBinding binds UEIdentityIndexValue to the PagingIEs object set of TS 36.413.
type PagingUEIdentityIndexValueIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UEIdentityIndexValueValueCodec
	inject func(s00.UEIdentityIndexValue,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.UEIdentityIndexValue,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingUEIdentityIndexValueIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingUEIdentityIndexValueIEBinding) Codec() s02.UEIdentityIndexValueValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingUEIdentityIndexValueIEBinding) New(value s00.UEIdentityIndexValue,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUEIdentityIndexValueValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingUEIdentityIndexValueIEBinding) Get(field *PagingIEField) (*s00.UEIdentityIndexValue,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingUEPagingIDIEBinding binds UEPagingID to the PagingIEs object set of TS 36.413.
type PagingUEPagingIDIEBinding struct {
	info   s00.FieldInfo
	codec  s36.UEPagingIDValueCodec
	inject func(s36.UEPagingID,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s36.UEPagingID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingUEPagingIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingUEPagingIDIEBinding) Codec() s36.UEPagingIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingUEPagingIDIEBinding) New(value s36.UEPagingID,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s36.BridgeUEPagingIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingUEPagingIDIEBinding) Get(field *PagingIEField) (*s36.UEPagingID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingPagingDRXIEBinding binds PagingDRX to the PagingIEs object set of TS 36.413.
type PagingPagingDRXIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PagingDRXValueCodec
	inject func(s00.PagingDRX,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.PagingDRX,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingPagingDRXIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingPagingDRXIEBinding) Codec() s01.PagingDRXValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingPagingDRXIEBinding) New(value s00.PagingDRX,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePagingDRXValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingPagingDRXIEBinding) Get(field *PagingIEField) (*s00.PagingDRX,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingCNDomainIEBinding binds CNDomain to the PagingIEs object set of TS 36.413.
type PagingCNDomainIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CNDomainValueCodec
	inject func(s00.CNDomain,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.CNDomain,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingCNDomainIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingCNDomainIEBinding) Codec() s00.CNDomainValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingCNDomainIEBinding) New(value s00.CNDomain,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCNDomainValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingCNDomainIEBinding) Get(field *PagingIEField) (*s00.CNDomain,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingTAIListIEBinding binds TAIList to the PagingIEs object set of TS 36.413.
type PagingTAIListIEBinding struct {
	info   s00.FieldInfo
	codec  s42.TAIListValueCodec
	inject func(s42.TAIList,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s42.TAIList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingTAIListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingTAIListIEBinding) Codec() s42.TAIListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingTAIListIEBinding) New(value s42.TAIList,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s42.BridgeTAIListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingTAIListIEBinding) Get(field *PagingIEField) (*s42.TAIList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingCSGIdListIEBinding binds CSGIdList to the PagingIEs object set of TS 36.413.
type PagingCSGIdListIEBinding struct {
	info   s00.FieldInfo
	codec  s17.CSGIdListValueCodec
	inject func(s17.CSGIdList,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s17.CSGIdList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingCSGIdListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingCSGIdListIEBinding) Codec() s17.CSGIdListValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingCSGIdListIEBinding) New(value s17.CSGIdList,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCSGIdListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingCSGIdListIEBinding) Get(field *PagingIEField) (*s17.CSGIdList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingPagingPriorityIEBinding binds PagingPriority to the PagingIEs object set of TS 36.413.
type PagingPagingPriorityIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PagingPriorityValueCodec
	inject func(s00.PagingPriority,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.PagingPriority,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingPagingPriorityIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingPagingPriorityIEBinding) Codec() s01.PagingPriorityValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingPagingPriorityIEBinding) New(value s00.PagingPriority,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePagingPriorityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingPagingPriorityIEBinding) Get(field *PagingIEField) (*s00.PagingPriority,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingUERadioCapabilityForPagingIEBinding binds UERadioCapabilityForPaging to the PagingIEs object set of TS 36.413.
type PagingUERadioCapabilityForPagingIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityForPagingValueCodec
	inject func(s00.UERadioCapabilityForPaging,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.UERadioCapabilityForPaging,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingUERadioCapabilityForPagingIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingUERadioCapabilityForPagingIEBinding) Codec() s02.UERadioCapabilityForPagingValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingUERadioCapabilityForPagingIEBinding) New(value s00.UERadioCapabilityForPaging,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityForPagingValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingUERadioCapabilityForPagingIEBinding) Get(field *PagingIEField) (*s00.UERadioCapabilityForPaging,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingAssistanceDataForPagingIEBinding binds AssistanceDataForPaging to the PagingIEs object set of TS 36.413.
type PagingAssistanceDataForPagingIEBinding struct {
	info   s00.FieldInfo
	codec  s31.AssistanceDataForPagingValueCodec
	inject func(s31.AssistanceDataForPaging,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s31.AssistanceDataForPaging,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingAssistanceDataForPagingIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingAssistanceDataForPagingIEBinding) Codec() s31.AssistanceDataForPagingValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingAssistanceDataForPagingIEBinding) New(value s31.AssistanceDataForPaging,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeAssistanceDataForPagingValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingAssistanceDataForPagingIEBinding) Get(field *PagingIEField) (*s31.AssistanceDataForPaging,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingPagingEDRXInformationIEBinding binds PagingEDRXInformation to the PagingIEs object set of TS 36.413.
type PagingPagingEDRXInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s23.PagingEDRXInformationValueCodec
	inject func(s23.PagingEDRXInformation,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s23.PagingEDRXInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingPagingEDRXInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingPagingEDRXInformationIEBinding) Codec() s23.PagingEDRXInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingPagingEDRXInformationIEBinding) New(value s23.PagingEDRXInformation,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s23.BridgePagingEDRXInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingPagingEDRXInformationIEBinding) Get(field *PagingIEField) (*s23.PagingEDRXInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingExtendedUEIdentityIndexValueIEBinding binds ExtendedUEIdentityIndexValue to the PagingIEs object set of TS 36.413.
type PagingExtendedUEIdentityIndexValueIEBinding struct {
	info   s00.FieldInfo
	codec  s01.ExtendedUEIdentityIndexValueValueCodec
	inject func(s00.ExtendedUEIdentityIndexValue,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.ExtendedUEIdentityIndexValue,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingExtendedUEIdentityIndexValueIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingExtendedUEIdentityIndexValueIEBinding) Codec() s01.ExtendedUEIdentityIndexValueValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingExtendedUEIdentityIndexValueIEBinding) New(value s00.ExtendedUEIdentityIndexValue,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeExtendedUEIdentityIndexValueValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingExtendedUEIdentityIndexValueIEBinding) Get(field *PagingIEField) (*s00.ExtendedUEIdentityIndexValue,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingNBIoTPagingEDRXInformationIEBinding binds NBIoTPagingEDRXInformation to the PagingIEs object set of TS 36.413.
type PagingNBIoTPagingEDRXInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s23.NBIoTPagingEDRXInformationValueCodec
	inject func(s23.NBIoTPagingEDRXInformation,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s23.NBIoTPagingEDRXInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingNBIoTPagingEDRXInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingNBIoTPagingEDRXInformationIEBinding) Codec() s23.NBIoTPagingEDRXInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingNBIoTPagingEDRXInformationIEBinding) New(value s23.NBIoTPagingEDRXInformation,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s23.BridgeNBIoTPagingEDRXInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingNBIoTPagingEDRXInformationIEBinding) Get(field *PagingIEField) (*s23.NBIoTPagingEDRXInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingNBIoTUEIdentityIndexValueIEBinding binds NBIoTUEIdentityIndexValue to the PagingIEs object set of TS 36.413.
type PagingNBIoTUEIdentityIndexValueIEBinding struct {
	info   s00.FieldInfo
	codec  s01.NBIoTUEIdentityIndexValueValueCodec
	inject func(s00.NBIoTUEIdentityIndexValue,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.NBIoTUEIdentityIndexValue,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingNBIoTUEIdentityIndexValueIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingNBIoTUEIdentityIndexValueIEBinding) Codec() s01.NBIoTUEIdentityIndexValueValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingNBIoTUEIdentityIndexValueIEBinding) New(value s00.NBIoTUEIdentityIndexValue,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNBIoTUEIdentityIndexValueValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingNBIoTUEIdentityIndexValueIEBinding) Get(field *PagingIEField) (*s00.NBIoTUEIdentityIndexValue,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingEnhancedCoverageRestrictedIEBinding binds EnhancedCoverageRestricted to the PagingIEs object set of TS 36.413.
type PagingEnhancedCoverageRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EnhancedCoverageRestrictedValueCodec
	inject func(s00.EnhancedCoverageRestricted,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.EnhancedCoverageRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingEnhancedCoverageRestrictedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingEnhancedCoverageRestrictedIEBinding) Codec() s00.EnhancedCoverageRestrictedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingEnhancedCoverageRestrictedIEBinding) New(value s00.EnhancedCoverageRestricted,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingEnhancedCoverageRestrictedIEBinding) Get(field *PagingIEField) (*s00.EnhancedCoverageRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingCEModeBRestrictedIEBinding binds CEModeBRestricted to the PagingIEs object set of TS 36.413.
type PagingCEModeBRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CEModeBRestrictedValueCodec
	inject func(s00.CEModeBRestricted,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.CEModeBRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingCEModeBRestrictedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingCEModeBRestrictedIEBinding) Codec() s00.CEModeBRestrictedValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingCEModeBRestrictedIEBinding) New(value s00.CEModeBRestricted,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingCEModeBRestrictedIEBinding) Get(field *PagingIEField) (*s00.CEModeBRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingDataSizeIEBinding binds DataSize to the PagingIEs object set of TS 36.413.
type PagingDataSizeIEBinding struct {
	info   s00.FieldInfo
	codec  s00.DataSizeValueCodec
	inject func(s00.DataSize,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.DataSize,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingDataSizeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingDataSizeIEBinding) Codec() s00.DataSizeValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingDataSizeIEBinding) New(value s00.DataSize,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeDataSizeValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingDataSizeIEBinding) Get(field *PagingIEField) (*s00.DataSize,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingWUSAssistanceInformationIEBinding binds WUSAssistanceInformation to the PagingIEs object set of TS 36.413.
type PagingWUSAssistanceInformationIEBinding struct {
	info   s00.FieldInfo
	codec  WUSAssistanceInformationValueCodec
	inject func(WUSAssistanceInformation,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*WUSAssistanceInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingWUSAssistanceInformationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingWUSAssistanceInformationIEBinding) Codec() WUSAssistanceInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b PagingWUSAssistanceInformationIEBinding) New(value WUSAssistanceInformation,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingWUSAssistanceInformationIEBinding) Get(field *PagingIEField) (*WUSAssistanceInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WUSAssistanceInformationValueCodec is the concrete ValueCodec[WUSAssistanceInformation].
type WUSAssistanceInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (WUSAssistanceInformation,

		error)
	encode func(WUSAssistanceInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(WUSAssistanceInformation, aper.DecodeState,

	) (WUSAssistanceInformation, aper.Snapshot,

	)
	compare func(WUSAssistanceInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WUSAssistanceInformationValueCodec) New(value WUSAssistanceInformation,

) (WUSAssistanceInformationAPERValue, error) {
	if c.encode == nil {
		return WUSAssistanceInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WUSAssistanceInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WUSAssistanceInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WUSAssistanceInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WUSAssistanceInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WUSAssistanceInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WUSAssistanceInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WUSAssistanceInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WUSAssistanceInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WUSAssistanceInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WUSAssistanceInformationValueCodec) EncodeAPER(value WUSAssistanceInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WUSAssistanceInformationValueCodec) encodeBudgetValue(value WUSAssistanceInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WUSAssistanceInformationValueCodec) encodeChanged(value WUSAssistanceInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingNBIoTPagingDRXIEBinding binds NBIoTPagingDRX to the PagingIEs object set of TS 36.413.
type PagingNBIoTPagingDRXIEBinding struct {
	info   s00.FieldInfo
	codec  s01.NBIoTPagingDRXValueCodec
	inject func(s00.NBIoTPagingDRX,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.NBIoTPagingDRX,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingNBIoTPagingDRXIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingNBIoTPagingDRXIEBinding) Codec() s01.NBIoTPagingDRXValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingNBIoTPagingDRXIEBinding) New(value s00.NBIoTPagingDRX,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeNBIoTPagingDRXValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingNBIoTPagingDRXIEBinding) Get(field *PagingIEField) (*s00.NBIoTPagingDRX,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingPagingCauseIEBinding binds PagingCause to the PagingIEs object set of TS 36.413.
type PagingPagingCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PagingCauseValueCodec
	inject func(s00.PagingCause,

	) PagingIEValue

	get func(*PagingIEValue,

	) (*s00.PagingCause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b PagingPagingCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PagingPagingCauseIEBinding) Codec() s01.PagingCauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b PagingPagingCauseIEBinding) New(value s00.PagingCause,

) (PagingIEField, error) {
	if b.inject == nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePagingCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return PagingIEField{}, aper.OperationError(err, "Value.New")
	}
	return PagingIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b PagingPagingCauseIEBinding) Get(field *PagingIEField) (*s00.PagingCause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// PagingValueCodec is the concrete ValueCodec[Paging].
type PagingValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (Paging,

		error)
	encode func(Paging,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(Paging, aper.DecodeState,

	) (Paging, aper.Snapshot,

	)
	compare func(Paging, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingValueCodec) New(value Paging,

) (PagingAPERValue, error) {
	if c.encode == nil {
		return PagingAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingValueCodec) EncodeAPER(value PagingAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PagingValueCodec) encodeBudgetValue(value Paging,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingValueCodec) encodeChanged(value Paging,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceStartValueCodec is the concrete ValueCodec[TraceStart].
type TraceStartValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TraceStart,

		error)
	encode func(TraceStart,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TraceStart, aper.DecodeState,

	) (TraceStart, aper.Snapshot,

	)
	compare func(TraceStart, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceStartValueCodec) New(value TraceStart,

) (TraceStartAPERValue, error) {
	if c.encode == nil {
		return TraceStartAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceStartAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceStartAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceStartAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceStartValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceStartAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceStartAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceStartAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceStartAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceStartAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceStartValueCodec) EncodeAPER(value TraceStartAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TraceStartValueCodec) encodeBudgetValue(value TraceStart,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceStartValueCodec) encodeChanged(value TraceStart,

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
func BridgePagingIEValueValidateS1APIEContainer(fields PagingIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = field.Value.rule().Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeTraceStartIEValueValidateS1APIEContainer(fields s60.TraceStartIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s60.BridgeTraceStartIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s60.BridgeTraceStartIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s60.BridgeTraceStartIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeTraceActivationExtIEsValueValidateS1APExtensionContainer(fields s59.TraceActivationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s59.TraceActivationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s59.TraceActivationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTraceActivationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeWLANMeasurementConfigurationExtIEsValueValidateS1APExtensionContainer(fields s14.WLANMeasurementConfigurationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s14.WLANMeasurementConfigurationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s14.WLANMeasurementConfigurationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeWLANMeasurementConfigurationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeWUSAssistanceInformationExtIEsValueValidateS1APExtensionContainer(fields s15.WUSAssistanceInformationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s25.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s15.WUSAssistanceInformationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldErr(&sealed) = err
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s15.WUSAssistanceInformationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeWUSAssistanceInformationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// PagingIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{PagingIEs}} codec of TS 36.413.
func PagingIEValueERABIEContainerListCodec(table s00.PagingIEValueIETable) PagingIEValueERABIEContainerListValueCodec {
	codec := PagingIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return PagingIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return PagingIEValueERABIEContainerListValueCodec{path: "PagingIEValueERABIEContainerList", decode: func(data []byte, options aper.DecodeState) (PagingIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PagingIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PagingIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
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
			return nil, runtime.WrapDecodePath(err, "PagingIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "PagingIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PagingIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value PagingIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PagingIEContainer(value), fresh, budget)
	}, capture: func(v PagingIEValueERABIEContainerList, options aper.DecodeState) (PagingIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePagingIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v PagingIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePagingIEValueCompareS1APERABIEContainerList(&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TraceStartIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{TraceStartIEs}} codec of TS 36.413.
func TraceStartIEValueERABIEContainerListCodec(table s00.TraceStartIEValueIETable) s60.TraceStartIEValueERABIEContainerListValueCodec {
	codec := TraceStartIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s60.BridgeTraceStartIEContainerValueCodecFieldDecode(&codec) == nil {
		return s60.TraceStartIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s60.TraceStartIEValueERABIEContainerListValueCodec {
		sealed := s60.TraceStartIEValueERABIEContainerListValueCodec{}
		*s60.BridgeTraceStartIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "TraceStartIEValueERABIEContainerList"
		*s60.BridgeTraceStartIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s60.TraceStartIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s60.TraceStartIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s60.TraceStartIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s60.BridgeTraceStartIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "TraceStartIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "TraceStartIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TraceStartIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s60.BridgeTraceStartIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s60.TraceStartIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s60.BridgeTraceStartIEContainerValueCodecFieldEncode(&codec))(s60.TraceStartIEContainer(value), fresh, budget)
		}
		*s60.BridgeTraceStartIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s60.TraceStartIEValueERABIEContainerList, options aper.DecodeState) (s60.TraceStartIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceStartIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s60.BridgeTraceStartIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s60.TraceStartIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTraceStartIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s60.BridgeTraceStartIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WUSAssistanceInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{WUS-Assistance-Information-ExtIEs}} codec of TS 36.413.
func WUSAssistanceInformationExtIEsValueExtensionFieldTableCodec(table s00.WUSAssistanceInformationExtIEsValueExtensionTable) s15.WUSAssistanceInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeWUSAssistanceInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s15.WUSAssistanceInformationExtIEsExtFieldValueCodec{}
	}
	return func() s15.WUSAssistanceInformationExtIEsExtFieldValueCodec {
		sealed := s15.WUSAssistanceInformationExtIEsExtFieldValueCodec{}
		*s15.BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldPath(&sealed) = "WUSAssistanceInformationExtIEsExtField"
		*s15.BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.WUSAssistanceInformationExtIEsExtField, error) {
			var field s14.WUSAssistanceInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s14.BridgeWUSAssistanceInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "WUSAssistanceInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "WUSAssistanceInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "WUSAssistanceInformationExtIEsExtField")
			}
			return field, nil
		}
		*s15.BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s14.WUSAssistanceInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s14.BridgeWUSAssistanceInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s15.BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s14.WUSAssistanceInformationExtIEsExtField, options aper.DecodeState) (s14.WUSAssistanceInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWUSAssistanceInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s15.BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s14.WUSAssistanceInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeWUSAssistanceInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WUSAssistanceInformationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{WUS-Assistance-Information-ExtIEs}} codec of TS 36.413.
func WUSAssistanceInformationExtIEsValueExtensionTableCodec(table s00.WUSAssistanceInformationExtIEsValueExtensionTable, bounds aper.ListBounds) s15.WUSAssistanceInformationExtIEsExtContainerValueCodec {
	if !*s00.BridgeWUSAssistanceInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s15.WUSAssistanceInformationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s15.WUSAssistanceInformationExtIEsExtContainerValueCodec {
		sealed := s15.WUSAssistanceInformationExtIEsExtContainerValueCodec{}
		*s15.BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldPath(&sealed) = "WUSAssistanceInformationExtIEsExtContainer"
		*s15.BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s15.WUSAssistanceInformationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s15.WUSAssistanceInformationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.WUSAssistanceInformationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeWUSAssistanceInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "WUSAssistanceInformationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "WUSAssistanceInformationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "WUSAssistanceInformationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s15.BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s15.WUSAssistanceInformationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s14.BridgeWUSAssistanceInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s15.BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s15.WUSAssistanceInformationExtIEsExtContainer, options aper.DecodeState) (s15.WUSAssistanceInformationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWUSAssistanceInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s15.BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s15.WUSAssistanceInformationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWUSAssistanceInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s15.BridgeWUSAssistanceInformationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PagingIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{PagingIEs}} codec of TS 36.413.
func PagingIEValueIEFieldTableCodec(table s00.PagingIEValueIETable) PagingIEFieldValueCodec {
	if !*s00.BridgePagingIEValueIETableFieldBound(&table) {
		return PagingIEFieldValueCodec{}
	}
	return PagingIEFieldValueCodec{path: "PagingIEField", decode: func(data []byte, options aper.DecodeState) (PagingIEField, error) {
		var field PagingIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "PagingIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "PagingIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "PagingIEField")
		}
		return field, nil
	}, encode: func(field PagingIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v PagingIEField, options aper.DecodeState) (PagingIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePagingIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v PagingIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePagingIEValueCompareS1APProtocolIEField(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TraceStartIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{TraceStartIEs}} codec of TS 36.413.
func TraceStartIEValueIEFieldTableCodec(table s00.TraceStartIEValueIETable) s60.TraceStartIEFieldValueCodec {
	if !*s00.BridgeTraceStartIEValueIETableFieldBound(&table) {
		return s60.TraceStartIEFieldValueCodec{}
	}
	return func() s60.TraceStartIEFieldValueCodec {
		sealed := s60.TraceStartIEFieldValueCodec{}
		*s60.BridgeTraceStartIEFieldValueCodecFieldPath(&sealed) = "TraceStartIEField"
		*s60.BridgeTraceStartIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s60.TraceStartIEField, error) {
			var field s60.TraceStartIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s60.BridgeTraceStartIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "TraceStartIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "TraceStartIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "TraceStartIEField")
			}
			return field, nil
		}
		*s60.BridgeTraceStartIEFieldValueCodecFieldEncode(&sealed) = func(field s60.TraceStartIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s60.BridgeTraceStartIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s60.BridgeTraceStartIEFieldValueCodecFieldCapture(&sealed) = func(v s60.TraceStartIEField, options aper.DecodeState) (s60.TraceStartIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceStartIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s60.BridgeTraceStartIEFieldValueCodecFieldCompare(&sealed) = func(v s60.TraceStartIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTraceStartIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s60.BridgeTraceStartIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PagingIEValueIETableCodec constructs the ProtocolIE-Container {{PagingIEs}} codec of TS 36.413.
func PagingIEValueIETableCodec(table s00.PagingIEValueIETable, bounds aper.ListBounds) PagingIEContainerValueCodec {
	if !*s00.BridgePagingIEValueIETableFieldBound(&table) {
		return PagingIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return PagingIEContainerValueCodec{path: "PagingIEContainer", decode: func(data []byte, options aper.DecodeState) (PagingIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PagingIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PagingIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
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
			return nil, runtime.WrapDecodePath(err, "PagingIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "PagingIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PagingIEContainer")
		}
		return fields, nil
	},
		encode: func(fields PagingIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := field.marshalAPERTo(bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}, capture: func(v PagingIEContainer, options aper.DecodeState) (PagingIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgePagingIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v PagingIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgePagingIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}

// TraceStartIEValueIETableCodec constructs the ProtocolIE-Container {{TraceStartIEs}} codec of TS 36.413.
func TraceStartIEValueIETableCodec(table s00.TraceStartIEValueIETable, bounds aper.ListBounds) s60.TraceStartIEContainerValueCodec {
	if !*s00.BridgeTraceStartIEValueIETableFieldBound(&table) {
		return s60.TraceStartIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s60.TraceStartIEContainerValueCodec {
		sealed := s60.TraceStartIEContainerValueCodec{}
		*s60.BridgeTraceStartIEContainerValueCodecFieldPath(&sealed) = "TraceStartIEContainer"
		*s60.BridgeTraceStartIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s60.TraceStartIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s60.TraceStartIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s60.TraceStartIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s60.BridgeTraceStartIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "TraceStartIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "TraceStartIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TraceStartIEContainer")
			}
			return fields, nil
		}
		*s60.BridgeTraceStartIEContainerValueCodecFieldEncode(&sealed) = func(fields s60.TraceStartIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s60.BridgeTraceStartIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s60.BridgeTraceStartIEContainerValueCodecFieldCapture(&sealed) = func(v s60.TraceStartIEContainer, options aper.DecodeState) (s60.TraceStartIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceStartIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s60.BridgeTraceStartIEContainerValueCodecFieldCompare(&sealed) = func(v s60.TraceStartIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTraceStartIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s60.BridgeTraceStartIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// PagingIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{PagingIEs}} codec of TS 36.413.
func PagingIEValueProtocolErrorIEContainerListCodec(table s00.PagingIEValueIETable) PagingIEValueProtocolErrorIEContainerListValueCodec {
	codec := PagingIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return PagingIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return PagingIEValueProtocolErrorIEContainerListValueCodec{path: "PagingIEValueProtocolErrorIEContainerList", decode: func(data []byte, options aper.DecodeState) (PagingIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PagingIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PagingIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
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
			return nil, runtime.WrapDecodePath(err, "PagingIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "PagingIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PagingIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value PagingIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PagingIEContainer(value), fresh, budget)
	}, capture: func(v PagingIEValueProtocolErrorIEContainerList, options aper.DecodeState) (PagingIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePagingIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v PagingIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgePagingIEValueCompareS1APProtocolErrorIEContainerList(
			&v,

			&s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TraceStartIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{TraceStartIEs}} codec of TS 36.413.
func TraceStartIEValueProtocolErrorIEContainerListCodec(table s00.TraceStartIEValueIETable) s60.TraceStartIEValueProtocolErrorIEContainerListValueCodec {
	codec := TraceStartIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s60.BridgeTraceStartIEContainerValueCodecFieldDecode(&codec) == nil {
		return s60.TraceStartIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s60.TraceStartIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s60.TraceStartIEValueProtocolErrorIEContainerListValueCodec{}
		*s60.BridgeTraceStartIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "TraceStartIEValueProtocolErrorIEContainerList"
		*s60.BridgeTraceStartIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s60.TraceStartIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s60.TraceStartIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s60.TraceStartIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s60.BridgeTraceStartIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "TraceStartIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "TraceStartIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TraceStartIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s60.BridgeTraceStartIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s60.TraceStartIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s60.BridgeTraceStartIEContainerValueCodecFieldEncode(&codec))(s60.TraceStartIEContainer(value), fresh, budget)
		}
		*s60.BridgeTraceStartIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s60.TraceStartIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s60.TraceStartIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceStartIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s60.BridgeTraceStartIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s60.TraceStartIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTraceStartIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s60.BridgeTraceStartIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PagingIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {PagingIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func PagingIEValueProtocolIEContainerListCodec(table s00.PagingIEValueIETable, bounds aper.ListBounds) PagingIEValueProtocolIEContainerListValueCodec {
	codec := PagingIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return PagingIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return PagingIEValueProtocolIEContainerListValueCodec{path: "PagingIEValueProtocolIEContainerList", decode: func(data []byte, options aper.DecodeState) (PagingIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields PagingIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field PagingIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
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
			return nil, runtime.WrapDecodePath(err, "PagingIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "PagingIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "PagingIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value PagingIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(PagingIEContainer(value), fresh, budget)
	}, capture: func(v PagingIEValueProtocolIEContainerList, options aper.DecodeState) (PagingIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgePagingIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v PagingIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgePagingIEValueCompareS1APProtocolIEContainerList(&v, &s)
		s.End(
			f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = bounds
		return sealed
	}(),
	}
}

// TraceStartIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {TraceStartIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func TraceStartIEValueProtocolIEContainerListCodec(table s00.TraceStartIEValueIETable, bounds aper.ListBounds) s60.TraceStartIEValueProtocolIEContainerListValueCodec {
	codec := TraceStartIEValueIETableCodec(table, bounds)
	if *s60.BridgeTraceStartIEContainerValueCodecFieldDecode(&codec) == nil {
		return s60.TraceStartIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s60.TraceStartIEValueProtocolIEContainerListValueCodec {
		sealed := s60.TraceStartIEValueProtocolIEContainerListValueCodec{}
		*s60.BridgeTraceStartIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "TraceStartIEValueProtocolIEContainerList"
		*s60.BridgeTraceStartIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s60.TraceStartIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s60.TraceStartIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s60.TraceStartIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s60.BridgeTraceStartIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "TraceStartIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "TraceStartIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TraceStartIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s60.BridgeTraceStartIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s60.TraceStartIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s60.BridgeTraceStartIEContainerValueCodecFieldEncode(&codec))(s60.TraceStartIEContainer(value), fresh, budget)
		}
		*s60.BridgeTraceStartIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s60.TraceStartIEValueProtocolIEContainerList, options aper.DecodeState) (s60.TraceStartIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceStartIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s60.BridgeTraceStartIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s60.TraceStartIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeTraceStartIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s60.BridgeTraceStartIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// pagingIEValueProtocolOpenValue is the concrete protocolOpenValue[PagingIEValue].
type PagingIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) PagingIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (PagingIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgePagingIEValueCaptureS1APProtocolIEField(v *PagingIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgePagingIEValueCompareS1APProtocolIEField(v *PagingIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// traceStartIEValueProtocolOpenValue is the concrete protocolOpenValue[TraceStartIEValue].
type TraceStartIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s60.TraceStartIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s60.TraceStartIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTraceStartIEValueCaptureS1APProtocolIEField(v *s60.TraceStartIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s60.BridgeTraceStartIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s60.BridgeTraceStartIEFieldFieldReplay(v), *s60.BridgeTraceStartIEFieldFieldWithoutReplay(v))
}
func BridgeTraceStartIEValueCompareS1APProtocolIEField(v *s60.TraceStartIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s60.BridgeTraceStartIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s60.BridgeTraceStartIEFieldFieldReplay(v), *s60.BridgeTraceStartIEFieldFieldWithoutReplay(v))
}

// wLANMeasurementConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[WLANMeasurementConfigurationExtIEsValue].
type WLANMeasurementConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.WLANMeasurementConfigurationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.WLANMeasurementConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// wUSAssistanceInformationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[WUSAssistanceInformationExtIEsValue].
type WUSAssistanceInformationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s08.WUSAssistanceInformationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s08.WUSAssistanceInformationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeWUSAssistanceInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s14.WUSAssistanceInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s08.BridgeWUSAssistanceInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s14.BridgeWUSAssistanceInformationExtIEsExtFieldFieldReplay(v), *s14.BridgeWUSAssistanceInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeWUSAssistanceInformationExtIEsValueCompareS1APProtocolExtensionField(v *s14.WUSAssistanceInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s08.BridgeWUSAssistanceInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s14.BridgeWUSAssistanceInformationExtIEsExtFieldFieldReplay(v), *s14.BridgeWUSAssistanceInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// WUSAssistanceInformationAPERValue is the concrete APERValue[WUSAssistanceInformation].
type WUSAssistanceInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   WUSAssistanceInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WUSAssistanceInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WUSAssistanceInformationAPERValue) WithoutReplay() WUSAssistanceInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingAPERValue is the concrete APERValue[Paging].
type PagingAPERValue struct {
	context s00.BridgeCodecContext
	Value   Paging

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingAPERValue) WithoutReplay() PagingAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TraceStartAPERValue is the concrete APERValue[TraceStart].
type TraceStartAPERValue struct {
	context s00.BridgeCodecContext
	Value   TraceStart

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceStartAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceStartAPERValue) WithoutReplay() TraceStartAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeTraceActivationExtIEsValueValidateS1APIEContainer(fields s59.TraceActivationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s59.BridgeTraceActivationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s59.BridgeTraceActivationExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s59.BridgeTraceActivationExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeWLANMeasurementConfigurationExtIEsValueValidateS1APIEContainer(fields s14.WLANMeasurementConfigurationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s07.BridgeWLANMeasurementConfigurationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeWLANMeasurementConfigurationExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s07.BridgeWLANMeasurementConfigurationExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeWUSAssistanceInformationExtIEsValueValidateS1APIEContainer(fields s15.WUSAssistanceInformationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s25.ValidationReport {
	report := func() s25.ValidationReport {
		sealed := s25.ValidationReport{Complete: true}
		*s25.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s25.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s25.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s25.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s08.BridgeWUSAssistanceInformationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s08.BridgeWUSAssistanceInformationExtIEsValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s08.BridgeWUSAssistanceInformationExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s16.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s31.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s31.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s31.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s25.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s25.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// PagingIEValueERABIEContainerListValueCodec is the concrete ValueCodec[PagingIEValueERABIEContainerList].
type PagingIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingIEValueERABIEContainerList, error)
	encode  func(PagingIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingIEValueERABIEContainerList, aper.DecodeState) (PagingIEValueERABIEContainerList, aper.Snapshot)
	compare func(PagingIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingIEValueERABIEContainerListValueCodec) New(value PagingIEValueERABIEContainerList) (PagingIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PagingIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingIEValueERABIEContainerListValueCodec) EncodeAPER(value PagingIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PagingIEValueERABIEContainerListValueCodec) encodeBudgetValue(value PagingIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingIEValueERABIEContainerListValueCodec) encodeChanged(value PagingIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingIEValueERABIEContainerList is E-RAB-IE-ContainerList {{PagingIEs}} of TS 36.413: a list of information element fields.
type PagingIEValueERABIEContainerList []PagingIEValueProtocolIESingleContainer

func BridgePagingIEValueCaptureS1APERABIEContainerList(v *PagingIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgePagingIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePagingIEValueCompareS1APERABIEContainerList(v *PagingIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgePagingIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTraceStartIEValueCaptureS1APERABIEContainerList(v *s60.TraceStartIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeTraceStartIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTraceStartIEValueCompareS1APERABIEContainerList(v *s60.TraceStartIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeTraceStartIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PagingIEFieldValueCodec is the concrete ValueCodec[PagingIEField].
type PagingIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingIEField, error)
	encode  func(PagingIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingIEField, aper.DecodeState) (PagingIEField, aper.Snapshot)
	compare func(PagingIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingIEFieldValueCodec) New(value PagingIEField) (PagingIEFieldAPERValue, error) {
	if c.encode == nil {
		return PagingIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingIEFieldValueCodec) EncodeAPER(value PagingIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PagingIEFieldValueCodec) encodeBudgetValue(value PagingIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingIEFieldValueCodec) encodeChanged(value PagingIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingIEContainerValueCodec is the concrete ValueCodec[PagingIEContainer].
type PagingIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingIEContainer, error)
	encode  func(PagingIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingIEContainer, aper.DecodeState) (PagingIEContainer, aper.Snapshot)
	compare func(PagingIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingIEContainerValueCodec) New(value PagingIEContainer) (PagingIEContainerAPERValue, error) {
	if c.encode == nil {
		return PagingIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingIEContainerValueCodec) EncodeAPER(value PagingIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PagingIEContainerValueCodec) encodeBudgetValue(value PagingIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingIEContainerValueCodec) encodeChanged(value PagingIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[PagingIEValueProtocolErrorIEContainerList].
type PagingIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingIEValueProtocolErrorIEContainerList, error)
	encode  func(PagingIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingIEValueProtocolErrorIEContainerList, aper.DecodeState) (PagingIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(PagingIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingIEValueProtocolErrorIEContainerListValueCodec) New(value PagingIEValueProtocolErrorIEContainerList) (PagingIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PagingIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value PagingIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PagingIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value PagingIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value PagingIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{PagingIEs}} of TS 36.413: a list of information element fields.
type PagingIEValueProtocolErrorIEContainerList []PagingIEValueProtocolIESingleContainer

func BridgePagingIEValueCaptureS1APProtocolErrorIEContainerList(v *PagingIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgePagingIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePagingIEValueCompareS1APProtocolErrorIEContainerList(v *PagingIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgePagingIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTraceStartIEValueCaptureS1APProtocolErrorIEContainerList(v *s60.TraceStartIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeTraceStartIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTraceStartIEValueCompareS1APProtocolErrorIEContainerList(v *s60.TraceStartIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeTraceStartIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PagingIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[PagingIEValueProtocolIEContainerList].
type PagingIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (PagingIEValueProtocolIEContainerList, error)
	encode  func(PagingIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(PagingIEValueProtocolIEContainerList, aper.DecodeState) (PagingIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(PagingIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingIEValueProtocolIEContainerListValueCodec) New(value PagingIEValueProtocolIEContainerList) (PagingIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return PagingIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingIEValueProtocolIEContainerListValueCodec) EncodeAPER(value PagingIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PagingIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value PagingIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingIEValueProtocolIEContainerListValueCodec) encodeChanged(value PagingIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {PagingIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type PagingIEValueProtocolIEContainerList []PagingIEValueProtocolIESingleContainer

func BridgePagingIEValueCaptureS1APProtocolIEContainerList(v *PagingIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgePagingIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgePagingIEValueCompareS1APProtocolIEContainerList(v *PagingIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgePagingIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTraceStartIEValueCaptureS1APProtocolIEContainerList(v *s60.TraceStartIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeTraceStartIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTraceStartIEValueCompareS1APProtocolIEContainerList(v *s60.TraceStartIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeTraceStartIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// PagingIEValueERABIEContainerListAPERValue is the concrete APERValue[PagingIEValueERABIEContainerList].
type PagingIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PagingIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingIEValueERABIEContainerListAPERValue) WithoutReplay() PagingIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{PagingIEs}} of TS 36.413: a single information element field.
type PagingIEValueProtocolIESingleContainer = PagingIEField

func BridgePagingIEValueCaptureS1APProtocolIESingleContainer(v *PagingIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePagingIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgePagingIEValueCompareS1APProtocolIESingleContainer(v *PagingIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePagingIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTraceStartIEValueCaptureS1APProtocolIESingleContainer(v *s60.TraceStartIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTraceStartIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeTraceStartIEValueCompareS1APProtocolIESingleContainer(v *s60.TraceStartIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTraceStartIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// PagingIEFieldAPERValue is the concrete APERValue[PagingIEField].
type PagingIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PagingIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingIEFieldAPERValue) WithoutReplay() PagingIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingIEContainerAPERValue is the concrete APERValue[PagingIEContainer].
type PagingIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PagingIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingIEContainerAPERValue) WithoutReplay() PagingIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[PagingIEValueProtocolErrorIEContainerList].
type PagingIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PagingIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() PagingIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingIEValueProtocolIEContainerListAPERValue is the concrete APERValue[PagingIEValueProtocolIEContainerList].
type PagingIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         PagingIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingIEValueProtocolIEContainerListAPERValue) WithoutReplay() PagingIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APPaging(v *Paging, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePagingIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APPaging(v *Paging, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgePagingIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APPagingIEValue(v *PagingIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(80):
			{
				f := s.Begin()
				s.Bool(v.rowUEIdentityIndexValue == nil)
				if v.rowUEIdentityIndexValue != nil {
					s00.BridgeCaptureS1APUEIdentityIndexValue(v.rowUEIdentityIndexValue, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(43):
			{
				f := s.Begin()
				s.Bool(v.rowUEPagingID == nil)
				if v.rowUEPagingID != nil {
					s36.BridgeCaptureS1APUEPagingID(v.rowUEPagingID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(44):
			{
				f := s.Begin()
				s.Bool(v.rowPagingDRX == nil)
				if v.rowPagingDRX != nil {
					s00.BridgeCaptureS1APPagingDRX(v.rowPagingDRX, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(109):
			{
				f := s.Begin()
				s.Bool(v.rowCNDomain == nil)
				if v.rowCNDomain != nil {
					s00.BridgeCaptureS1APCNDomain(v.rowCNDomain, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(46):
			{
				f := s.Begin()
				s.Bool(v.rowTAIList == nil)
				if v.rowTAIList != nil {
					s42.BridgeCaptureS1APTAIList(v.rowTAIList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(128):
			{
				f := s.Begin()
				s.Bool(v.rowCSGIdList == nil)
				if v.rowCSGIdList != nil {
					s25.BridgeCaptureS1APCSGIdList(v.rowCSGIdList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(151):
			{
				f := s.Begin()
				s.Bool(v.rowPagingPriority == nil)
				if v.rowPagingPriority != nil {
					s00.BridgeCaptureS1APPagingPriority(v.rowPagingPriority, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(198):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityForPaging == nil)
				if v.rowUERadioCapabilityForPaging != nil {
					s00.BridgeCaptureS1APUERadioCapabilityForPaging(v.rowUERadioCapabilityForPaging, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(211):
			{
				f := s.Begin()
				s.Bool(v.rowAssistanceDataForPaging == nil)
				if v.rowAssistanceDataForPaging != nil {
					s31.BridgeCaptureS1APAssistanceDataForPaging(v.rowAssistanceDataForPaging, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(227):
			{
				f := s.Begin()
				s.Bool(v.rowPagingEDRXInformation == nil)
				if v.rowPagingEDRXInformation != nil {
					s23.BridgeCaptureS1APPagingEDRXInformation(v.rowPagingEDRXInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(231):
			{
				f := s.Begin()
				s.Bool(v.rowExtendedUEIdentityIndexValue == nil)
				if v.rowExtendedUEIdentityIndexValue != nil {
					s00.BridgeCaptureS1APExtendedUEIdentityIndexValue(v.rowExtendedUEIdentityIndexValue, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(239):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTPagingEDRXInformation == nil)
				if v.rowNBIoTPagingEDRXInformation != nil {
					s23.BridgeCaptureS1APNBIoTPagingEDRXInformation(v.rowNBIoTPagingEDRXInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(244):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTUEIdentityIndexValue == nil)
				if v.rowNBIoTUEIdentityIndexValue != nil {
					s00.BridgeCaptureS1APNBIoTUEIdentityIndexValue(v.rowNBIoTUEIdentityIndexValue, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(251):
			{
				f := s.Begin()
				s.Bool(v.rowEnhancedCoverageRestricted == nil)
				if v.rowEnhancedCoverageRestricted != nil {
					s00.BridgeCaptureS1APEnhancedCoverageRestricted(v.rowEnhancedCoverageRestricted, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(271):
			{
				f := s.Begin()
				s.Bool(v.rowCEModeBRestricted == nil)
				if v.rowCEModeBRestricted != nil {
					s00.BridgeCaptureS1APCEModeBRestricted(v.rowCEModeBRestricted, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(304):
			{
				f := s.Begin()
				s.Bool(v.rowDataSize == nil)
				if v.rowDataSize != nil {
					s00.BridgeCaptureS1APDataSize(v.rowDataSize, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(323):
			{
				f := s.Begin()
				s.Bool(v.rowWUSAssistanceInformation == nil)
				if v.rowWUSAssistanceInformation != nil {
					BridgeCaptureS1APWUSAssistanceInformation(v.rowWUSAssistanceInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(324):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTPagingDRX == nil)
				if v.rowNBIoTPagingDRX != nil {
					s00.BridgeCaptureS1APNBIoTPagingDRX(v.rowNBIoTPagingDRX, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(331):
			{
				f := s.Begin()
				s.Bool(v.rowPagingCause == nil)
				if v.rowPagingCause != nil {
					s00.BridgeCaptureS1APPagingCause(v.rowPagingCause, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v PagingIEValue) captureSemantics(s aper.SemanticCapture) PagingIEValue {
	BridgeCaptureS1APPagingIEValue(&v, &s)
	return v
}
func BridgeCompareS1APPagingIEValue(v *PagingIEValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(80):
			{
				f := s.Begin()
				s.Bool(v.rowUEIdentityIndexValue == nil)
				if v.rowUEIdentityIndexValue != nil {
					s08.BridgeCompareS1APUEIdentityIndexValue(v.rowUEIdentityIndexValue, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(43):
			{
				f := s.Begin()
				s.Bool(v.rowUEPagingID == nil)
				if v.rowUEPagingID != nil {
					s36.BridgeCompareS1APUEPagingID(v.rowUEPagingID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(44):
			{
				f := s.Begin()
				s.Bool(v.rowPagingDRX == nil)
				if v.rowPagingDRX != nil {
					s02.BridgeCompareS1APPagingDRX(v.rowPagingDRX, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(109):
			{
				f := s.Begin()
				s.Bool(v.rowCNDomain == nil)
				if v.rowCNDomain != nil {
					s02.BridgeCompareS1APCNDomain(v.rowCNDomain, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(46):
			{
				f := s.Begin()
				s.Bool(v.rowTAIList == nil)
				if v.rowTAIList != nil {
					s42.BridgeCompareS1APTAIList(v.rowTAIList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(128):
			{
				f := s.Begin()
				s.Bool(v.rowCSGIdList == nil)
				if v.rowCSGIdList != nil {
					s25.BridgeCompareS1APCSGIdList(v.rowCSGIdList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(151):
			{
				f := s.Begin()
				s.Bool(v.rowPagingPriority == nil)
				if v.rowPagingPriority != nil {
					s02.BridgeCompareS1APPagingPriority(v.rowPagingPriority, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(198):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityForPaging == nil)
				if v.rowUERadioCapabilityForPaging != nil {
					s08.BridgeCompareS1APUERadioCapabilityForPaging(v.rowUERadioCapabilityForPaging, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(211):
			{
				f := s.Begin()
				s.Bool(v.rowAssistanceDataForPaging == nil)
				if v.rowAssistanceDataForPaging != nil {
					s31.BridgeCompareS1APAssistanceDataForPaging(v.rowAssistanceDataForPaging, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(227):
			{
				f := s.Begin()
				s.Bool(v.rowPagingEDRXInformation == nil)
				if v.rowPagingEDRXInformation != nil {
					s23.BridgeCompareS1APPagingEDRXInformation(v.rowPagingEDRXInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(231):
			{
				f := s.Begin()
				s.Bool(v.rowExtendedUEIdentityIndexValue == nil)
				if v.rowExtendedUEIdentityIndexValue != nil {
					s02.BridgeCompareS1APExtendedUEIdentityIndexValue(v.rowExtendedUEIdentityIndexValue, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(239):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTPagingEDRXInformation == nil)
				if v.rowNBIoTPagingEDRXInformation != nil {
					s23.BridgeCompareS1APNBIoTPagingEDRXInformation(v.rowNBIoTPagingEDRXInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(244):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTUEIdentityIndexValue == nil)
				if v.rowNBIoTUEIdentityIndexValue != nil {
					s02.BridgeCompareS1APNBIoTUEIdentityIndexValue(v.rowNBIoTUEIdentityIndexValue, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(251):
			{
				f := s.Begin()
				s.Bool(v.rowEnhancedCoverageRestricted == nil)
				if v.rowEnhancedCoverageRestricted != nil {
					s02.BridgeCompareS1APEnhancedCoverageRestricted(v.rowEnhancedCoverageRestricted, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(271):
			{
				f := s.Begin()
				s.Bool(v.rowCEModeBRestricted == nil)
				if v.rowCEModeBRestricted != nil {
					s02.BridgeCompareS1APCEModeBRestricted(v.rowCEModeBRestricted, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(304):
			{
				f := s.Begin()
				s.Bool(v.rowDataSize == nil)
				if v.rowDataSize != nil {
					s02.BridgeCompareS1APDataSize(v.rowDataSize, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(323):
			{
				f := s.Begin()
				s.Bool(v.rowWUSAssistanceInformation == nil)
				if v.rowWUSAssistanceInformation != nil {
					BridgeCompareS1APWUSAssistanceInformation(v.rowWUSAssistanceInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(324):
			{
				f := s.Begin()
				s.Bool(v.rowNBIoTPagingDRX == nil)
				if v.rowNBIoTPagingDRX != nil {
					s02.BridgeCompareS1APNBIoTPagingDRX(v.rowNBIoTPagingDRX, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(331):
			{
				f := s.Begin()
				s.Bool(v.rowPagingCause == nil)
				if v.rowPagingCause != nil {
					s02.BridgeCompareS1APPagingCause(v.rowPagingCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v PagingIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APPagingIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APTraceStart(v *TraceStart, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTraceStartIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTraceStart(v *TraceStart, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTraceStartIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APWUSAssistanceInformation(v *WUSAssistanceInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPagingProbabilityInformation(&v.PagingProbabilityInformation, s)
	s.Bool(v.IEExtensions == nil)
	BridgeWUSAssistanceInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APWUSAssistanceInformation(v *WUSAssistanceInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APPagingProbabilityInformation(&v.PagingProbabilityInformation, s)
	s.Bool(v.IEExtensions == nil)
	BridgeWUSAssistanceInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}

// WUSAssistanceInformation represents the ASN.1 type WUS-Assistance-Information (SEQUENCE).
type WUSAssistanceInformation struct {
	replay                       aper.Snapshot
	stream                       aper.WireSpan
	received                     bool
	withoutReplay                bool
	receivedAbsolute             bool
	receivedBytes                aper.WireSpan
	receivedLocation             aper.Location
	PagingProbabilityInformation s00.PagingProbabilityInformation               `asn1:"tag:0,context,implicit"`
	IEExtensions                 s15.WUSAssistanceInformationExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef            bool                                           `asn1:"-" json:"-"`
	extCount                     int64                                          `asn1:"-" json:"-"`
	extPresent                   []bool                                         `asn1:"-" json:"-"`
	extData                      [][]byte                                       `asn1:"-" json:"-"`
	perPadding                   aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding                []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin                    []aper.OpaqueOrigin
	extWire                      []aper.WireSpan
}

// MarshalAPER encodes WUSAssistanceInformation to APER format.
func (v *WUSAssistanceInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *WUSAssistanceInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.PagingProbabilityInformation), 21, true); err != nil {
		return fmt.Errorf("encoding pagingProbabilityInformation: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s14.BridgeWUSAssistanceInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
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
	return nil
}

// UnmarshalAPER decodes WUSAssistanceInformation from APER format.
func (v *WUSAssistanceInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *WUSAssistanceInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "WUSAssistanceInformation")
	}
	bb.EnterComponent("WUSAssistanceInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "WUSAssistanceInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "WUSAssistanceInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "WUSAssistanceInformation")
	}
	v.perPadding = padding
	return nil
}
func (v *WUSAssistanceInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WUSAssistanceInformation{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pagingprobabilityinformation, err := aper.DecodeEnumeratedAligned(bb, 21, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PagingProbabilityInformation"})
	if err != nil {
		return runtime.WrapDecodePath(err, "PagingProbabilityInformation")
	}
	v.PagingProbabilityInformation = s00.PagingProbabilityInformation(val_pagingprobabilityinformation)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s15.WUSAssistanceInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s14.WUSAssistanceInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s14.BridgeWUSAssistanceInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WUSAssistanceInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "WUSAssistanceInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "WUSAssistanceInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WUSAssistanceInformation) WithoutReplay() WUSAssistanceInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero WUSAssistanceInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *WUSAssistanceInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *WUSAssistanceInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("WUSAssistanceInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("WUSAssistanceInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *WUSAssistanceInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("WUSAssistanceInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("WUSAssistanceInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *WUSAssistanceInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "WUSAssistanceInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *WUSAssistanceInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "WUSAssistanceInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APWUSAssistanceInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "WUSAssistanceInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "WUSAssistanceInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *WUSAssistanceInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "WUSAssistanceInformation")
}
func (v *WUSAssistanceInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "WUSAssistanceInformation")
}
func (v *WUSAssistanceInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APWUSAssistanceInformation(v, &s)
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
func (v *WUSAssistanceInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *WUSAssistanceInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *WUSAssistanceInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "WUSAssistanceInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded WUSAssistanceInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APWUSAssistanceInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = WUSAssistanceInformation{}
		return report, aper.OperationError(err, "WUSAssistanceInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "WUSAssistanceInformation")
}

// Paging represents the ASN.1 type Paging (SEQUENCE).
type Paging struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      PagingIEContainer      `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                   `asn1:"-" json:"-"`
	extCount         int64                  `asn1:"-" json:"-"`
	extPresent       []bool                 `asn1:"-" json:"-"`
	extData          [][]byte               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// TraceStart represents the ASN.1 type TraceStart (SEQUENCE).
type TraceStart struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s60.TraceStartIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                      `asn1:"-" json:"-"`
	extCount         int64                     `asn1:"-" json:"-"`
	extPresent       []bool                    `asn1:"-" json:"-"`
	extData          [][]byte                  `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding         `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding    `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes Paging to APER format.
func (v *Paging) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *Paging) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

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
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
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
	return nil
}

// UnmarshalAPER decodes Paging from APER format.
func (v *Paging) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *Paging) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "Paging")
	}
	bb.EnterComponent("Paging")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Paging")
	}
	padding, err := aper.CaptureFinalBits(bb, "Paging")
	if err != nil {
		return runtime.WrapDecodePath(err, "Paging")
	}
	v.perPadding = padding
	return nil
}
func (v *Paging) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = Paging{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(PagingIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem PagingIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes TraceStart to APER format.
func (v *TraceStart) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TraceStart) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = s16.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

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
			if err := s60.BridgeTraceStartIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:436
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:440
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:447
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
	return nil
}

// UnmarshalAPER decodes TraceStart from APER format.
func (v *TraceStart) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *TraceStart) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TraceStart")
	}
	bb.EnterComponent("TraceStart")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TraceStart")
	}
	padding, err := aper.CaptureFinalBits(bb, "TraceStart")
	if err != nil {
		return runtime.WrapDecodePath(err, "TraceStart")
	}
	v.perPadding = padding
	return nil
}
func (v *TraceStart) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TraceStart{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s60.TraceStartIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s60.TraceStartIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s60.BridgeTraceStartIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:624
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:627
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *Paging) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "Paging", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "Paging", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v Paging) WithoutReplay() Paging {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero Paging
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TraceStart) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "TraceStart", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TraceStart", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TraceStart) WithoutReplay() TraceStart {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TraceStart
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *Paging) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *Paging) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("Paging.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("Paging.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *Paging) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("Paging.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("Paging.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TraceStart) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TraceStart) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TraceStart.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TraceStart.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TraceStart) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TraceStart.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TraceStart.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *Paging) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "Paging")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *Paging) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "Paging")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APPaging(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "Paging")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "Paging")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *Paging) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "Paging")
}
func (v *Paging) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "Paging")
}
func (v *Paging) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APPaging(v, &s)
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
func (v *Paging) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *Paging) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *TraceStart) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TraceStart")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TraceStart) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TraceStart")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTraceStart(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TraceStart")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TraceStart")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TraceStart) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TraceStart")
}
func (v *TraceStart) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TraceStart")
}
func (v *TraceStart) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTraceStart(v, &s)
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
func (v *TraceStart) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TraceStart) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *Paging) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "Paging")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded Paging
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APPaging(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = Paging{}
		return report, aper.OperationError(err, "Paging")
	}
	*v = decoded
	return report, aper.OperationError(nil, "Paging")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TraceStart) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TraceStart")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TraceStart
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTraceStart(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TraceStart{}
		return report, aper.OperationError(err, "TraceStart")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TraceStart")
}

type PagingIEValue struct {
	id                              s00.ProtocolIEID
	received                        aper.WireSpan
	replay                          aper.Snapshot
	opaque                          aper.OpaqueOpenType
	isOpaque                        bool
	rowUEIdentityIndexValue         *s00.UEIdentityIndexValue
	rowUEPagingID                   *s36.UEPagingID
	rowPagingDRX                    *s00.PagingDRX
	rowCNDomain                     *s00.CNDomain
	rowTAIList                      *s42.TAIList
	rowCSGIdList                    *s17.CSGIdList
	rowPagingPriority               *s00.PagingPriority
	rowUERadioCapabilityForPaging   *s00.UERadioCapabilityForPaging
	rowAssistanceDataForPaging      *s31.AssistanceDataForPaging
	rowPagingEDRXInformation        *s23.PagingEDRXInformation
	rowExtendedUEIdentityIndexValue *s00.ExtendedUEIdentityIndexValue
	rowNBIoTPagingEDRXInformation   *s23.NBIoTPagingEDRXInformation
	rowNBIoTUEIdentityIndexValue    *s00.NBIoTUEIdentityIndexValue
	rowEnhancedCoverageRestricted   *s00.EnhancedCoverageRestricted
	rowCEModeBRestricted            *s00.CEModeBRestricted
	rowDataSize                     *s00.DataSize
	rowWUSAssistanceInformation     *WUSAssistanceInformation
	rowNBIoTPagingDRX               *s00.NBIoTPagingDRX
	rowPagingCause                  *s00.PagingCause
}

func (v PagingIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(80):
		return v.rowUEIdentityIndexValue != nil
	case s00.ProtocolIEID(43):
		return v.rowUEPagingID != nil
	case s00.ProtocolIEID(44):
		return v.rowPagingDRX != nil
	case s00.ProtocolIEID(109):
		return v.rowCNDomain != nil
	case s00.ProtocolIEID(46):
		return v.rowTAIList != nil
	case s00.ProtocolIEID(128):
		return v.rowCSGIdList != nil
	case s00.ProtocolIEID(151):
		return v.rowPagingPriority != nil
	case s00.ProtocolIEID(198):
		return v.rowUERadioCapabilityForPaging != nil
	case s00.ProtocolIEID(211):
		return v.rowAssistanceDataForPaging != nil
	case s00.ProtocolIEID(227):
		return v.rowPagingEDRXInformation != nil
	case s00.ProtocolIEID(231):
		return v.rowExtendedUEIdentityIndexValue != nil
	case s00.ProtocolIEID(239):
		return v.rowNBIoTPagingEDRXInformation != nil
	case s00.ProtocolIEID(244):
		return v.rowNBIoTUEIdentityIndexValue != nil
	case s00.ProtocolIEID(251):
		return v.rowEnhancedCoverageRestricted != nil
	case s00.ProtocolIEID(271):
		return v.rowCEModeBRestricted != nil
	case s00.ProtocolIEID(304):
		return v.rowDataSize != nil
	case s00.ProtocolIEID(323):
		return v.rowWUSAssistanceInformation != nil
	case s00.ProtocolIEID(324):
		return v.rowNBIoTPagingDRX != nil
	case s00.ProtocolIEID(331):
		return v.rowPagingCause != nil
	}
	return false
}

// Opaque returns the retained opaque open value of PagingIEValue and reports whether the opaque alternative is selected.
func (v *PagingIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (PagingIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs"}}
}
func (PagingIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(80):
		return aper.UnknownSelector
	case s00.ProtocolIEID(43):
		return aper.UnknownSelector
	case s00.ProtocolIEID(44):
		return aper.UnknownSelector
	case s00.ProtocolIEID(109):
		return aper.UnknownSelector
	case s00.ProtocolIEID(46):
		return aper.UnknownSelector
	case s00.ProtocolIEID(128):
		return aper.UnknownSelector
	case s00.ProtocolIEID(151):
		return aper.UnknownSelector
	case s00.ProtocolIEID(198):
		return aper.UnknownSelector
	case s00.ProtocolIEID(211):
		return aper.UnknownSelector
	case s00.ProtocolIEID(227):
		return aper.UnknownSelector
	case s00.ProtocolIEID(231):
		return aper.UnknownSelector
	case s00.ProtocolIEID(239):
		return aper.UnknownSelector
	case s00.ProtocolIEID(244):
		return aper.UnknownSelector
	case s00.ProtocolIEID(251):
		return aper.UnknownSelector
	case s00.ProtocolIEID(271):
		return aper.UnknownSelector
	case s00.ProtocolIEID(304):
		return aper.UnknownSelector
	case s00.ProtocolIEID(323):
		return aper.UnknownSelector
	case s00.ProtocolIEID(324):
		return aper.UnknownSelector
	case s00.ProtocolIEID(331):
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
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
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
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
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

// AsUEIdentityIndexValue returns the selected UEIdentityIndexValue value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsUEIdentityIndexValue() (*s00.UEIdentityIndexValue, bool) {
	if v == nil || v.id != s00.ProtocolIEID(80) || v.rowUEIdentityIndexValue == nil {
		return nil, false
	}
	return v.rowUEIdentityIndexValue, true
}

// AsUEPagingID returns the selected UEPagingID value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsUEPagingID() (*s36.UEPagingID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(43) || v.rowUEPagingID == nil {
		return nil, false
	}
	return v.rowUEPagingID, true
}

// AsPagingDRX returns the selected PagingDRX value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsPagingDRX() (*s00.PagingDRX, bool) {
	if v == nil || v.id != s00.ProtocolIEID(44) || v.rowPagingDRX == nil {
		return nil, false
	}
	return v.rowPagingDRX, true
}

// AsCNDomain returns the selected CNDomain value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsCNDomain() (*s00.CNDomain, bool) {
	if v == nil || v.id != s00.ProtocolIEID(109) || v.rowCNDomain == nil {
		return nil, false
	}
	return v.rowCNDomain, true
}

// AsTAIList returns the selected TAIList value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsTAIList() (*s42.TAIList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(46) || v.rowTAIList == nil {
		return nil, false
	}
	return v.rowTAIList, true
}

// AsCSGIdList returns the selected CSGIdList value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsCSGIdList() (*s17.CSGIdList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(128) || v.rowCSGIdList == nil {
		return nil, false
	}
	return v.rowCSGIdList, true
}

// AsPagingPriority returns the selected PagingPriority value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsPagingPriority() (*s00.PagingPriority, bool) {
	if v == nil || v.id != s00.ProtocolIEID(151) || v.rowPagingPriority == nil {
		return nil, false
	}
	return v.rowPagingPriority, true
}

// AsUERadioCapabilityForPaging returns the selected UERadioCapabilityForPaging value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsUERadioCapabilityForPaging() (*s00.UERadioCapabilityForPaging, bool) {
	if v == nil || v.id != s00.ProtocolIEID(198) || v.rowUERadioCapabilityForPaging == nil {
		return nil, false
	}
	return v.rowUERadioCapabilityForPaging, true
}

// AsAssistanceDataForPaging returns the selected AssistanceDataForPaging value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsAssistanceDataForPaging() (*s31.AssistanceDataForPaging, bool) {
	if v == nil || v.id != s00.ProtocolIEID(211) || v.rowAssistanceDataForPaging == nil {
		return nil, false
	}
	return v.rowAssistanceDataForPaging, true
}

// AsPagingEDRXInformation returns the selected PagingEDRXInformation value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsPagingEDRXInformation() (*s23.PagingEDRXInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(227) || v.rowPagingEDRXInformation == nil {
		return nil, false
	}
	return v.rowPagingEDRXInformation, true
}

// AsExtendedUEIdentityIndexValue returns the selected ExtendedUEIdentityIndexValue value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsExtendedUEIdentityIndexValue() (*s00.ExtendedUEIdentityIndexValue, bool) {
	if v == nil || v.id != s00.ProtocolIEID(231) || v.rowExtendedUEIdentityIndexValue == nil {
		return nil, false
	}
	return v.rowExtendedUEIdentityIndexValue, true
}

// AsNBIoTPagingEDRXInformation returns the selected NBIoTPagingEDRXInformation value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsNBIoTPagingEDRXInformation() (*s23.NBIoTPagingEDRXInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(239) || v.rowNBIoTPagingEDRXInformation == nil {
		return nil, false
	}
	return v.rowNBIoTPagingEDRXInformation, true
}

// AsNBIoTUEIdentityIndexValue returns the selected NBIoTUEIdentityIndexValue value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsNBIoTUEIdentityIndexValue() (*s00.NBIoTUEIdentityIndexValue, bool) {
	if v == nil || v.id != s00.ProtocolIEID(244) || v.rowNBIoTUEIdentityIndexValue == nil {
		return nil, false
	}
	return v.rowNBIoTUEIdentityIndexValue, true
}

// AsEnhancedCoverageRestricted returns the selected EnhancedCoverageRestricted value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsEnhancedCoverageRestricted() (*s00.EnhancedCoverageRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(251) || v.rowEnhancedCoverageRestricted == nil {
		return nil, false
	}
	return v.rowEnhancedCoverageRestricted, true
}

// AsCEModeBRestricted returns the selected CEModeBRestricted value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsCEModeBRestricted() (*s00.CEModeBRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(271) || v.rowCEModeBRestricted == nil {
		return nil, false
	}
	return v.rowCEModeBRestricted, true
}

// AsDataSize returns the selected DataSize value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsDataSize() (*s00.DataSize, bool) {
	if v == nil || v.id != s00.ProtocolIEID(304) || v.rowDataSize == nil {
		return nil, false
	}
	return v.rowDataSize, true
}

// AsWUSAssistanceInformation returns the selected WUSAssistanceInformation value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsWUSAssistanceInformation() (*WUSAssistanceInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(323) || v.rowWUSAssistanceInformation == nil {
		return nil, false
	}
	return v.rowWUSAssistanceInformation, true
}

// AsNBIoTPagingDRX returns the selected NBIoTPagingDRX value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsNBIoTPagingDRX() (*s00.NBIoTPagingDRX, bool) {
	if v == nil || v.id != s00.ProtocolIEID(324) || v.rowNBIoTPagingDRX == nil {
		return nil, false
	}
	return v.rowNBIoTPagingDRX, true
}

// AsPagingCause returns the selected PagingCause value of PagingIEValue and reports whether that alternative is active.
func (v *PagingIEValue) AsPagingCause() (*s00.PagingCause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(331) || v.rowPagingCause == nil {
		return nil, false
	}
	return v.rowPagingCause, true
}
func (v PagingIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (PagingIEValue, error) {
	out := PagingIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(80):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.UEIdentityIndexValue, error) {
			var v struct{ Value s00.UEIdentityIndexValue }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 10, 10, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
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
		out.rowUEIdentityIndexValue = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(43):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s36.UEPagingID
		child := scope
		if err := s36.BridgeUEPagingIDMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UEPagingID:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEPagingID")
		if err != nil {
			return out, err
		}
		*s36.BridgeUEPagingIDFieldPerPadding(&value) = padding.Padding()
		*s36.BridgeUEPagingIDFieldReceived(&value) = true
		raw.RetainContents(s36.BridgeUEPagingIDFieldReceivedBytes(&value))
		*s36.BridgeUEPagingIDFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUEPagingID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(44):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PagingDRX"})
		value := s00.PagingDRX(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "PagingDRX:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowPagingDRX = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(109):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "CNDomain"})
		value := s00.CNDomain(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CNDomain:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCNDomain = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(46):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s55.BridgeUnmarshalAPERTAIListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "TAIList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowTAIList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(128):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s48.BridgeUnmarshalAPERCSGIdListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CSGIdList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowCSGIdList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(151):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 8, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PagingPriority"})
		value := s00.PagingPriority(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "PagingPriority:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowPagingPriority = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(198):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.UERadioCapabilityForPaging, error) {
			var v struct {
				Value s00.UERadioCapabilityForPaging
			}
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.UERadioCapabilityForPaging(val_value)
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
		out.rowUERadioCapabilityForPaging = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(211):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s31.AssistanceDataForPaging
		child := scope
		if err := s31.BridgeAssistanceDataForPagingMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "AssistanceDataForPaging:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "AssistanceDataForPaging")
		if err != nil {
			return out, err
		}
		*s31.BridgeAssistanceDataForPagingFieldPerPadding(&value) = padding
		*s31.BridgeAssistanceDataForPagingFieldReceived(&value) = true
		raw.RetainContents(s31.BridgeAssistanceDataForPagingFieldReceivedBytes(&value))
		*s31.BridgeAssistanceDataForPagingFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowAssistanceDataForPaging = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(227):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s23.PagingEDRXInformation
		child := scope
		if err := s23.BridgePagingEDRXInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "PagingEDRXInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PagingEDRXInformation")
		if err != nil {
			return out, err
		}
		*s23.BridgePagingEDRXInformationFieldPerPadding(&value) = padding
		*s23.BridgePagingEDRXInformationFieldReceived(&value) = true
		raw.RetainContents(s23.BridgePagingEDRXInformationFieldReceivedBytes(&value))
		*s23.BridgePagingEDRXInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowPagingEDRXInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(231):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.ExtendedUEIdentityIndexValue, error) {
			var v struct {
				Value s00.ExtendedUEIdentityIndexValue
			}
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 14, 14, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
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
		out.rowExtendedUEIdentityIndexValue = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(239):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s23.NBIoTPagingEDRXInformation
		child := scope
		if err := s23.BridgeNBIoTPagingEDRXInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NBIoTPagingEDRXInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NBIoTPagingEDRXInformation")
		if err != nil {
			return out, err
		}
		*s23.BridgeNBIoTPagingEDRXInformationFieldPerPadding(&value) = padding
		*s23.BridgeNBIoTPagingEDRXInformationFieldReceived(&value) = true
		raw.RetainContents(s23.BridgeNBIoTPagingEDRXInformationFieldReceivedBytes(&value))
		*s23.BridgeNBIoTPagingEDRXInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNBIoTPagingEDRXInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(244):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.NBIoTUEIdentityIndexValue, error) {
			var v struct{ Value s00.NBIoTUEIdentityIndexValue }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 12, 12, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
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
		out.rowNBIoTUEIdentityIndexValue = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(251):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EnhancedCoverageRestricted"})
		value := s00.EnhancedCoverageRestricted(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "EnhancedCoverageRestricted:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowEnhancedCoverageRestricted = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(271):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CEModeBRestricted"})
		value := s00.CEModeBRestricted(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CEModeBRestricted:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCEModeBRestricted = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(304):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound12, true)
		value := s00.DataSize(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "DataSize:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowDataSize = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(323):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value WUSAssistanceInformation
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "WUSAssistanceInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "WUSAssistanceInformation")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowWUSAssistanceInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(324):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 6, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NBIoTPagingDRX"})
		value := s00.NBIoTPagingDRX(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "NBIoTPagingDRX:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowNBIoTPagingDRX = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(331):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PagingCause"})
		value := s00.PagingCause(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "PagingCause:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowPagingCause = &value
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
func (v PagingIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v PagingIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(80):
		if v.rowUEIdentityIndexValue == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-UEIdentityIndexValue:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.UEIdentityIndexValue, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.UEIdentityIndexValue }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 10, 10, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowUEIdentityIndexValue, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(43):
		if v.rowUEPagingID == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-UEPagingID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s36.BridgeUEPagingIDMethodMarshalAPERBudget(v.rowUEPagingID, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(44):
		if v.rowPagingDRX == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-pagingDRX:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowPagingDRX), 4, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(109):
		if v.rowCNDomain == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-CNDomain:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCNDomain), 2, false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(46):
		if v.rowTAIList == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-TAIList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s55.TAIListComplete{Value: *v.rowTAIList}
		candidate, err := s55.BridgeTAIListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(128):
		if v.rowCSGIdList == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-CSG-IdList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s48.CSGIdListComplete{Value: *v.rowCSGIdList}
		candidate, err := s48.BridgeCSGIdListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(151):
		if v.rowPagingPriority == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-PagingPriority:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowPagingPriority), 8, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(198):
		if v.rowUERadioCapabilityForPaging == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-UERadioCapabilityForPaging:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.UERadioCapabilityForPaging, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.UERadioCapabilityForPaging
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
		})(*v.rowUERadioCapabilityForPaging, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(211):
		if v.rowAssistanceDataForPaging == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-AssistanceDataForPaging:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s31.BridgeAssistanceDataForPagingMethodMarshalAPERBudget(v.rowAssistanceDataForPaging, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(227):
		if v.rowPagingEDRXInformation == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-Paging-eDRXInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s23.BridgePagingEDRXInformationMethodMarshalAPERBudget(v.rowPagingEDRXInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(231):
		if v.rowExtendedUEIdentityIndexValue == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-extended-UEIdentityIndexValue:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.ExtendedUEIdentityIndexValue, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.ExtendedUEIdentityIndexValue
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 14, 14, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowExtendedUEIdentityIndexValue, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(239):
		if v.rowNBIoTPagingEDRXInformation == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-NB-IoT-Paging-eDRXInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s23.BridgeNBIoTPagingEDRXInformationMethodMarshalAPERBudget(v.rowNBIoTPagingEDRXInformation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(244):
		if v.rowNBIoTUEIdentityIndexValue == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-NB-IoT-UEIdentityIndexValue:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.NBIoTUEIdentityIndexValue, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.NBIoTUEIdentityIndexValue }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 12, 12, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowNBIoTUEIdentityIndexValue, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(251):
		if v.rowEnhancedCoverageRestricted == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-EnhancedCoverageRestricted:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowEnhancedCoverageRestricted), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(271):
		if v.rowCEModeBRestricted == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-CE-ModeBRestricted:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCEModeBRestricted), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(304):
		if v.rowDataSize == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-DataSize:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowDataSize, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound12, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(323):
		if v.rowWUSAssistanceInformation == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-WUS-Assistance-Information:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowWUSAssistanceInformation.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(324):
		if v.rowNBIoTPagingDRX == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-NB-IoT-PagingDRX:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowNBIoTPagingDRX), 6, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(331):
		if v.rowPagingCause == nil {
			return nil, fmt.Errorf("%s missing value", "PagingIEs.id-PagingCause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowPagingCause), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "PagingIEValue:", v.id)
	}
}

type PagingIETable struct{}

func PagingIEs() PagingIETable { return PagingIETable{} }

// ID returns the ASN.1 object-set identity of PagingIETable.
func (PagingIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by PagingIETable.
func (PagingIETable) Table() s00.PagingIEValueIETable {
	return func() s00.PagingIEValueIETable {
		sealed := s00.PagingIEValueIETable{}
		*s00.BridgePagingIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (PagingIETable) infoUEIdentityIndexValue() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(80), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEIdentityIndexValue"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-UEIdentityIndexValue"}}}
}

// UEIdentityIndexValue returns the typed binding for the UEIdentityIndexValue row of PagingIETable.
func (t PagingIETable) UEIdentityIndexValue() PagingUEIdentityIndexValueIEBinding {
	return PagingUEIdentityIndexValueIEBinding{info: t.infoUEIdentityIndexValue(), codec: func() s02.UEIdentityIndexValueValueCodec {
		sealed := s02.UEIdentityIndexValueValueCodec{}
		*s02.BridgeUEIdentityIndexValueValueCodecFieldPath(&sealed) = "UEIdentityIndexValue"
		*s02.BridgeUEIdentityIndexValueValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UEIdentityIndexValue, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UEIdentityIndexValue
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEIdentityIndexValue")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(80), raw)
			if err != nil {
				var empty s00.UEIdentityIndexValue
				return empty, runtime.WrapDecodePath(err, "UEIdentityIndexValue")
			}
			value, ok := decoded.AsUEIdentityIndexValue()
			if !ok {
				var empty s00.UEIdentityIndexValue
				return empty, fmt.Errorf("binding PagingIEs.id-UEIdentityIndexValue: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUEIdentityIndexValueValueCodecFieldEncode(&sealed) = func(value s00.UEIdentityIndexValue, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(80), rowUEIdentityIndexValue: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUEIdentityIndexValueValueCodecFieldCapture(&sealed) = func(v s00.UEIdentityIndexValue, options aper.DecodeState) (s00.UEIdentityIndexValue, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUEIdentityIndexValue(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeUEIdentityIndexValueValueCodecFieldCompare(&sealed) = func(v s00.UEIdentityIndexValue, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APUEIdentityIndexValue(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeUEIdentityIndexValueValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEIdentityIndexValue"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UEIdentityIndexValue) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(80), rowUEIdentityIndexValue: &value}
		}, get: func(value *PagingIEValue) (*s00.UEIdentityIndexValue, bool) { return value.AsUEIdentityIndexValue() }}
}
func (PagingIETable) infoUEPagingID() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(43), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEPagingID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-UEPagingID"}}}
}

// UEPagingID returns the typed binding for the UEPagingID row of PagingIETable.
func (t PagingIETable) UEPagingID() PagingUEPagingIDIEBinding {
	return PagingUEPagingIDIEBinding{info: t.infoUEPagingID(), codec: func() s36.UEPagingIDValueCodec {
		sealed := s36.UEPagingIDValueCodec{}
		*s36.BridgeUEPagingIDValueCodecFieldPath(&sealed) = "UEPagingID"
		*s36.BridgeUEPagingIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEPagingID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s36.UEPagingID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEPagingID")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(43), raw)
			if err != nil {
				var empty s36.UEPagingID
				return empty, runtime.WrapDecodePath(err, "UEPagingID")
			}
			value, ok := decoded.AsUEPagingID()
			if !ok {
				var empty s36.UEPagingID
				return empty, fmt.Errorf("binding PagingIEs.id-UEPagingID: no selected value")
			}
			return *value, nil
		}
		*s36.BridgeUEPagingIDValueCodecFieldEncode(&sealed) = func(value s36.UEPagingID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(43), rowUEPagingID: &value}).encodeFresh(fresh, budget)
		}
		*s36.BridgeUEPagingIDValueCodecFieldCapture(&sealed) = func(v s36.UEPagingID, options aper.DecodeState) (s36.UEPagingID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s36.BridgeCaptureS1APUEPagingID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s36.BridgeUEPagingIDValueCodecFieldCompare(&sealed) = func(v s36.UEPagingID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeCompareS1APUEPagingID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s36.BridgeUEPagingIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEPagingID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s36.UEPagingID) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(43), rowUEPagingID: &value}
		}, get: func(value *PagingIEValue) (*s36.UEPagingID, bool) { return value.AsUEPagingID() }}
}
func (PagingIETable) infoPagingDRX() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(44), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PagingDRX"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-pagingDRX"}}}
}

// PagingDRX returns the typed binding for the PagingDRX row of PagingIETable.
func (t PagingIETable) PagingDRX() PagingPagingDRXIEBinding {
	return PagingPagingDRXIEBinding{info: t.infoPagingDRX(), codec: func() s01.PagingDRXValueCodec {
		sealed := s01.PagingDRXValueCodec{}
		*s01.BridgePagingDRXValueCodecFieldPath(&sealed) = "PagingDRX"
		*s01.BridgePagingDRXValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PagingDRX, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PagingDRX
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PagingDRX")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(44), raw)
			if err != nil {
				var empty s00.PagingDRX
				return empty, runtime.WrapDecodePath(err, "PagingDRX")
			}
			value, ok := decoded.AsPagingDRX()
			if !ok {
				var empty s00.PagingDRX
				return empty, fmt.Errorf("binding PagingIEs.id-pagingDRX: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePagingDRXValueCodecFieldEncode(&sealed) = func(value s00.PagingDRX, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(44), rowPagingDRX: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgePagingDRXValueCodecFieldCapture(&sealed) = func(v s00.PagingDRX, options aper.DecodeState) (s00.PagingDRX, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APPagingDRX(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePagingDRXValueCodecFieldCompare(&sealed) = func(v s00.PagingDRX, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPagingDRX(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePagingDRXValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PagingDRX"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.PagingDRX) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(44), rowPagingDRX: &value}
		}, get: func(value *PagingIEValue) (*s00.PagingDRX, bool) { return value.AsPagingDRX() }}
}
func (PagingIETable) infoCNDomain() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(109), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CNDomain"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-CNDomain"}}}
}

// CNDomain returns the typed binding for the CNDomain row of PagingIETable.
func (t PagingIETable) CNDomain() PagingCNDomainIEBinding {
	return PagingCNDomainIEBinding{info: t.infoCNDomain(), codec: func() s00.CNDomainValueCodec {
		sealed := s00.CNDomainValueCodec{}
		*s00.BridgeCNDomainValueCodecFieldPath(&sealed) = "CNDomain"
		*s00.BridgeCNDomainValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CNDomain, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CNDomain
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CNDomain")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(109), raw)
			if err != nil {
				var empty s00.CNDomain
				return empty, runtime.WrapDecodePath(err, "CNDomain")
			}
			value, ok := decoded.AsCNDomain()
			if !ok {
				var empty s00.CNDomain
				return empty, fmt.Errorf("binding PagingIEs.id-CNDomain: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCNDomainValueCodecFieldEncode(&sealed) = func(value s00.CNDomain, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(109), rowCNDomain: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCNDomainValueCodecFieldCapture(&sealed) = func(v s00.CNDomain, options aper.DecodeState) (s00.CNDomain, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APCNDomain(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCNDomainValueCodecFieldCompare(&sealed) = func(v s00.CNDomain, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCNDomain(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCNDomainValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CNDomain"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CNDomain) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(109), rowCNDomain: &value}
		}, get: func(value *PagingIEValue) (*s00.CNDomain, bool) { return value.AsCNDomain() }}
}
func (PagingIETable) infoTAIList() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(46), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TAIList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-TAIList"}}}
}

// TAIList returns the typed binding for the TAIList row of PagingIETable.
func (t PagingIETable) TAIList() PagingTAIListIEBinding {
	return PagingTAIListIEBinding{info: t.infoTAIList(), codec: func() s42.TAIListValueCodec {
		sealed := s42.TAIListValueCodec{}
		*s42.BridgeTAIListValueCodecFieldPath(&sealed) = "TAIList"
		*s42.BridgeTAIListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s42.TAIList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s42.TAIList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TAIList")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(46), raw)
			if err != nil {
				var empty s42.TAIList
				return empty, runtime.WrapDecodePath(err, "TAIList")
			}
			value, ok := decoded.AsTAIList()
			if !ok {
				var empty s42.TAIList
				return empty, fmt.Errorf("binding PagingIEs.id-TAIList: no selected value")
			}
			return *value, nil
		}
		*s42.BridgeTAIListValueCodecFieldEncode(&sealed) = func(value s42.TAIList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(46), rowTAIList: &value}).encodeFresh(fresh, budget)
		}
		*s42.BridgeTAIListValueCodecFieldCapture(&sealed) = func(v s42.TAIList, options aper.DecodeState) (s42.TAIList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s42.BridgeCaptureS1APTAIList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s42.BridgeTAIListValueCodecFieldCompare(&sealed) = func(v s42.TAIList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s42.BridgeCompareS1APTAIList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s42.BridgeTAIListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TAIList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s42.TAIList) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(46), rowTAIList: &value}
		}, get: func(value *PagingIEValue) (*s42.TAIList, bool) { return value.AsTAIList() }}
}
func (PagingIETable) infoCSGIdList() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(128), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSG-IdList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-CSG-IdList"}}}
}

// CSGIdList returns the typed binding for the CSGIdList row of PagingIETable.
func (t PagingIETable) CSGIdList() PagingCSGIdListIEBinding {
	return PagingCSGIdListIEBinding{info: t.infoCSGIdList(), codec: func() s17.CSGIdListValueCodec {
		sealed := s17.CSGIdListValueCodec{}
		*s17.BridgeCSGIdListValueCodecFieldPath(&sealed) = "CSGIdList"
		*s17.BridgeCSGIdListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.CSGIdList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.CSGIdList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGIdList")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(128), raw)
			if err != nil {
				var empty s17.CSGIdList
				return empty, runtime.WrapDecodePath(err, "CSGIdList")
			}
			value, ok := decoded.AsCSGIdList()
			if !ok {
				var empty s17.CSGIdList
				return empty, fmt.Errorf("binding PagingIEs.id-CSG-IdList: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeCSGIdListValueCodecFieldEncode(&sealed) = func(value s17.CSGIdList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(128), rowCSGIdList: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeCSGIdListValueCodecFieldCapture(&sealed) = func(v s17.CSGIdList, options aper.DecodeState) (s17.CSGIdList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s25.BridgeCaptureS1APCSGIdList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s17.BridgeCSGIdListValueCodecFieldCompare(&sealed) = func(v s17.CSGIdList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s25.BridgeCompareS1APCSGIdList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCSGIdListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGIdList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.CSGIdList) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(128), rowCSGIdList: &value}
		}, get: func(value *PagingIEValue) (*s17.CSGIdList, bool) { return value.AsCSGIdList() }}
}
func (PagingIETable) infoPagingPriority() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(151), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PagingPriority"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-PagingPriority"}}}
}

// PagingPriority returns the typed binding for the PagingPriority row of PagingIETable.
func (t PagingIETable) PagingPriority() PagingPagingPriorityIEBinding {
	return PagingPagingPriorityIEBinding{info: t.infoPagingPriority(), codec: func() s01.PagingPriorityValueCodec {
		sealed := s01.PagingPriorityValueCodec{}
		*s01.BridgePagingPriorityValueCodecFieldPath(&sealed) = "PagingPriority"
		*s01.BridgePagingPriorityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PagingPriority, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PagingPriority
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PagingPriority")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(151), raw)
			if err != nil {
				var empty s00.PagingPriority
				return empty, runtime.WrapDecodePath(err, "PagingPriority")
			}
			value, ok := decoded.AsPagingPriority()
			if !ok {
				var empty s00.PagingPriority
				return empty, fmt.Errorf("binding PagingIEs.id-PagingPriority: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePagingPriorityValueCodecFieldEncode(&sealed) = func(value s00.PagingPriority, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(151), rowPagingPriority: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgePagingPriorityValueCodecFieldCapture(&sealed) = func(v s00.PagingPriority, options aper.DecodeState) (s00.PagingPriority, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPagingPriority(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePagingPriorityValueCodecFieldCompare(&sealed) = func(v s00.PagingPriority, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPagingPriority(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePagingPriorityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PagingPriority"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.PagingPriority) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(151), rowPagingPriority: &value}
		}, get: func(value *PagingIEValue) (*s00.PagingPriority, bool) { return value.AsPagingPriority() }}
}
func (PagingIETable) infoUERadioCapabilityForPaging() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(198), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapabilityForPaging"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-UERadioCapabilityForPaging"}}}
}

// UERadioCapabilityForPaging returns the typed binding for the UERadioCapabilityForPaging row of PagingIETable.
func (t PagingIETable) UERadioCapabilityForPaging() PagingUERadioCapabilityForPagingIEBinding {
	return PagingUERadioCapabilityForPagingIEBinding{info: t.infoUERadioCapabilityForPaging(), codec: func() s02.UERadioCapabilityForPagingValueCodec {
		sealed := s02.UERadioCapabilityForPagingValueCodec{}
		*s02.BridgeUERadioCapabilityForPagingValueCodecFieldPath(&sealed) = "UERadioCapabilityForPaging"
		*s02.BridgeUERadioCapabilityForPagingValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapabilityForPaging, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapabilityForPaging
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UERadioCapabilityForPaging")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(198), raw)
			if err != nil {
				var empty s00.UERadioCapabilityForPaging
				return empty, runtime.WrapDecodePath(err, "UERadioCapabilityForPaging")
			}
			value, ok := decoded.AsUERadioCapabilityForPaging()
			if !ok {
				var empty s00.UERadioCapabilityForPaging
				return empty, fmt.Errorf("binding PagingIEs.id-UERadioCapabilityForPaging: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityForPagingValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapabilityForPaging, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(198), rowUERadioCapabilityForPaging: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUERadioCapabilityForPagingValueCodecFieldCapture(&sealed) = func(v s00.UERadioCapabilityForPaging, options aper.DecodeState) (s00.UERadioCapabilityForPaging, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUERadioCapabilityForPaging(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s02.BridgeUERadioCapabilityForPagingValueCodecFieldCompare(&sealed) = func(v s00.UERadioCapabilityForPaging, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s08.BridgeCompareS1APUERadioCapabilityForPaging(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeUERadioCapabilityForPagingValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERadioCapabilityForPaging"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UERadioCapabilityForPaging) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(198), rowUERadioCapabilityForPaging: &value}
		}, get: func(value *PagingIEValue) (*s00.UERadioCapabilityForPaging, bool) {
			return value.AsUERadioCapabilityForPaging()
		}}
}
func (PagingIETable) infoAssistanceDataForPaging() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(211), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AssistanceDataForPaging"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-AssistanceDataForPaging"}}}
}

// AssistanceDataForPaging returns the typed binding for the AssistanceDataForPaging row of PagingIETable.
func (t PagingIETable) AssistanceDataForPaging() PagingAssistanceDataForPagingIEBinding {
	return PagingAssistanceDataForPagingIEBinding{info: t.infoAssistanceDataForPaging(), codec: func() s31.AssistanceDataForPagingValueCodec {
		sealed := s31.AssistanceDataForPagingValueCodec{}
		*s31.BridgeAssistanceDataForPagingValueCodecFieldPath(&sealed) = "AssistanceDataForPaging"
		*s31.BridgeAssistanceDataForPagingValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.AssistanceDataForPaging, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.AssistanceDataForPaging
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AssistanceDataForPaging")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(211), raw)
			if err != nil {
				var empty s31.AssistanceDataForPaging
				return empty, runtime.WrapDecodePath(err, "AssistanceDataForPaging")
			}
			value, ok := decoded.AsAssistanceDataForPaging()
			if !ok {
				var empty s31.AssistanceDataForPaging
				return empty, fmt.Errorf("binding PagingIEs.id-AssistanceDataForPaging: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeAssistanceDataForPagingValueCodecFieldEncode(&sealed) = func(value s31.AssistanceDataForPaging, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(211), rowAssistanceDataForPaging: &value}).encodeFresh(fresh, budget)
		}
		*s31.BridgeAssistanceDataForPagingValueCodecFieldCapture(&sealed) = func(v s31.AssistanceDataForPaging, options aper.DecodeState) (s31.AssistanceDataForPaging, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s31.BridgeCaptureS1APAssistanceDataForPaging(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s31.BridgeAssistanceDataForPagingValueCodecFieldCompare(&sealed) = func(v s31.AssistanceDataForPaging, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APAssistanceDataForPaging(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeAssistanceDataForPagingValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceDataForPaging"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.AssistanceDataForPaging) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(211), rowAssistanceDataForPaging: &value}
		}, get: func(value *PagingIEValue) (*s31.AssistanceDataForPaging, bool) {
			return value.AsAssistanceDataForPaging()
		}}
}
func (PagingIETable) infoPagingEDRXInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(227), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Paging-eDRXInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-Paging-eDRXInformation"}}}
}

// PagingEDRXInformation returns the typed binding for the PagingEDRXInformation row of PagingIETable.
func (t PagingIETable) PagingEDRXInformation() PagingPagingEDRXInformationIEBinding {
	return PagingPagingEDRXInformationIEBinding{info: t.infoPagingEDRXInformation(), codec: func() s23.PagingEDRXInformationValueCodec {
		sealed := s23.PagingEDRXInformationValueCodec{}
		*s23.BridgePagingEDRXInformationValueCodecFieldPath(&sealed) = "PagingEDRXInformation"
		*s23.BridgePagingEDRXInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.PagingEDRXInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s23.PagingEDRXInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PagingEDRXInformation")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(227), raw)
			if err != nil {
				var empty s23.PagingEDRXInformation
				return empty, runtime.WrapDecodePath(err, "PagingEDRXInformation")
			}
			value, ok := decoded.AsPagingEDRXInformation()
			if !ok {
				var empty s23.PagingEDRXInformation
				return empty, fmt.Errorf("binding PagingIEs.id-Paging-eDRXInformation: no selected value")
			}
			return *value, nil
		}
		*s23.BridgePagingEDRXInformationValueCodecFieldEncode(&sealed) = func(value s23.PagingEDRXInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(227), rowPagingEDRXInformation: &value}).encodeFresh(fresh, budget)
		}
		*s23.BridgePagingEDRXInformationValueCodecFieldCapture(&sealed) = func(v s23.PagingEDRXInformation, options aper.DecodeState) (s23.PagingEDRXInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s23.BridgeCaptureS1APPagingEDRXInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s23.BridgePagingEDRXInformationValueCodecFieldCompare(&sealed) = func(v s23.PagingEDRXInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s23.BridgeCompareS1APPagingEDRXInformation(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgePagingEDRXInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PagingEDRXInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s23.PagingEDRXInformation) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(227), rowPagingEDRXInformation: &value}
		}, get: func(value *PagingIEValue) (*s23.PagingEDRXInformation, bool) { return value.AsPagingEDRXInformation() }}
}
func (PagingIETable) infoExtendedUEIdentityIndexValue() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(231), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Extended-UEIdentityIndexValue"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-extended-UEIdentityIndexValue"}}}
}

// ExtendedUEIdentityIndexValue returns the typed binding for the ExtendedUEIdentityIndexValue row of PagingIETable.
func (t PagingIETable) ExtendedUEIdentityIndexValue() PagingExtendedUEIdentityIndexValueIEBinding {
	return PagingExtendedUEIdentityIndexValueIEBinding{info: t.infoExtendedUEIdentityIndexValue(), codec: func() s01.ExtendedUEIdentityIndexValueValueCodec {
		sealed := s01.ExtendedUEIdentityIndexValueValueCodec{}
		*s01.BridgeExtendedUEIdentityIndexValueValueCodecFieldPath(&sealed) = "ExtendedUEIdentityIndexValue"
		*s01.BridgeExtendedUEIdentityIndexValueValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ExtendedUEIdentityIndexValue, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ExtendedUEIdentityIndexValue
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ExtendedUEIdentityIndexValue")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(231), raw)
			if err != nil {
				var empty s00.ExtendedUEIdentityIndexValue
				return empty, runtime.WrapDecodePath(err, "ExtendedUEIdentityIndexValue")
			}
			value, ok := decoded.AsExtendedUEIdentityIndexValue()
			if !ok {
				var empty s00.ExtendedUEIdentityIndexValue
				return empty, fmt.Errorf("binding PagingIEs.id-extended-UEIdentityIndexValue: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeExtendedUEIdentityIndexValueValueCodecFieldEncode(&sealed) = func(value s00.ExtendedUEIdentityIndexValue, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(231), rowExtendedUEIdentityIndexValue: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeExtendedUEIdentityIndexValueValueCodecFieldCapture(&sealed) = func(v s00.ExtendedUEIdentityIndexValue, options aper.DecodeState) (s00.ExtendedUEIdentityIndexValue, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APExtendedUEIdentityIndexValue(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeExtendedUEIdentityIndexValueValueCodecFieldCompare(&sealed) = func(v s00.ExtendedUEIdentityIndexValue, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			s02.BridgeCompareS1APExtendedUEIdentityIndexValue(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeExtendedUEIdentityIndexValueValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ExtendedUEIdentityIndexValue"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ExtendedUEIdentityIndexValue) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(231), rowExtendedUEIdentityIndexValue: &value}
		}, get: func(value *PagingIEValue) (*s00.ExtendedUEIdentityIndexValue, bool) {
			return value.AsExtendedUEIdentityIndexValue()
		}}
}
func (PagingIETable) infoNBIoTPagingEDRXInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(239), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NB-IoT-Paging-eDRXInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-NB-IoT-Paging-eDRXInformation"}}}
}

// NBIoTPagingEDRXInformation returns the typed binding for the NBIoTPagingEDRXInformation row of PagingIETable.
func (t PagingIETable) NBIoTPagingEDRXInformation() PagingNBIoTPagingEDRXInformationIEBinding {
	return PagingNBIoTPagingEDRXInformationIEBinding{info: t.infoNBIoTPagingEDRXInformation(), codec: func() s23.NBIoTPagingEDRXInformationValueCodec {
		sealed := s23.NBIoTPagingEDRXInformationValueCodec{}
		*s23.BridgeNBIoTPagingEDRXInformationValueCodecFieldPath(&sealed) = "NBIoTPagingEDRXInformation"
		*s23.BridgeNBIoTPagingEDRXInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.NBIoTPagingEDRXInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s23.NBIoTPagingEDRXInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NBIoTPagingEDRXInformation")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(239), raw)
			if err != nil {
				var empty s23.NBIoTPagingEDRXInformation
				return empty, runtime.WrapDecodePath(err, "NBIoTPagingEDRXInformation")
			}
			value, ok := decoded.AsNBIoTPagingEDRXInformation()
			if !ok {
				var empty s23.NBIoTPagingEDRXInformation
				return empty, fmt.Errorf("binding PagingIEs.id-NB-IoT-Paging-eDRXInformation: no selected value")
			}
			return *value, nil
		}
		*s23.BridgeNBIoTPagingEDRXInformationValueCodecFieldEncode(&sealed) = func(value s23.NBIoTPagingEDRXInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(239), rowNBIoTPagingEDRXInformation: &value}).encodeFresh(fresh, budget)
		}
		*s23.BridgeNBIoTPagingEDRXInformationValueCodecFieldCapture(&sealed) = func(v s23.NBIoTPagingEDRXInformation, options aper.DecodeState) (s23.NBIoTPagingEDRXInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s23.BridgeCaptureS1APNBIoTPagingEDRXInformation(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s23.BridgeNBIoTPagingEDRXInformationValueCodecFieldCompare(&sealed) = func(v s23.NBIoTPagingEDRXInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s23.BridgeCompareS1APNBIoTPagingEDRXInformation(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeNBIoTPagingEDRXInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NBIoTPagingEDRXInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s23.NBIoTPagingEDRXInformation) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(239), rowNBIoTPagingEDRXInformation: &value}
		}, get: func(value *PagingIEValue) (*s23.NBIoTPagingEDRXInformation, bool) {
			return value.AsNBIoTPagingEDRXInformation()
		}}
}
func (PagingIETable) infoNBIoTUEIdentityIndexValue() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(244), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NB-IoT-UEIdentityIndexValue"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-NB-IoT-UEIdentityIndexValue"}}}
}

// NBIoTUEIdentityIndexValue returns the typed binding for the NBIoTUEIdentityIndexValue row of PagingIETable.
func (t PagingIETable) NBIoTUEIdentityIndexValue() PagingNBIoTUEIdentityIndexValueIEBinding {
	return PagingNBIoTUEIdentityIndexValueIEBinding{info: t.infoNBIoTUEIdentityIndexValue(), codec: func() s01.NBIoTUEIdentityIndexValueValueCodec {
		sealed := s01.NBIoTUEIdentityIndexValueValueCodec{}
		*s01.BridgeNBIoTUEIdentityIndexValueValueCodecFieldPath(&sealed) = "NBIoTUEIdentityIndexValue"
		*s01.BridgeNBIoTUEIdentityIndexValueValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NBIoTUEIdentityIndexValue, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NBIoTUEIdentityIndexValue
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NBIoTUEIdentityIndexValue")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(244), raw)
			if err != nil {
				var empty s00.NBIoTUEIdentityIndexValue
				return empty, runtime.WrapDecodePath(err, "NBIoTUEIdentityIndexValue")
			}
			value, ok := decoded.AsNBIoTUEIdentityIndexValue()
			if !ok {
				var empty s00.NBIoTUEIdentityIndexValue
				return empty, fmt.Errorf("binding PagingIEs.id-NB-IoT-UEIdentityIndexValue: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNBIoTUEIdentityIndexValueValueCodecFieldEncode(&sealed) = func(value s00.NBIoTUEIdentityIndexValue, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(244), rowNBIoTUEIdentityIndexValue: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeNBIoTUEIdentityIndexValueValueCodecFieldCapture(&sealed) = func(v s00.NBIoTUEIdentityIndexValue, options aper.DecodeState) (s00.NBIoTUEIdentityIndexValue, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNBIoTUEIdentityIndexValue(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s01.BridgeNBIoTUEIdentityIndexValueValueCodecFieldCompare(&sealed) = func(v s00.NBIoTUEIdentityIndexValue, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNBIoTUEIdentityIndexValue(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNBIoTUEIdentityIndexValueValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NBIoTUEIdentityIndexValue"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.NBIoTUEIdentityIndexValue) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(244), rowNBIoTUEIdentityIndexValue: &value}
		}, get: func(value *PagingIEValue) (*s00.NBIoTUEIdentityIndexValue, bool) {
			return value.AsNBIoTUEIdentityIndexValue()
		}}
}
func (PagingIETable) infoEnhancedCoverageRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(251), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EnhancedCoverageRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-EnhancedCoverageRestricted"}}}
}

// EnhancedCoverageRestricted returns the typed binding for the EnhancedCoverageRestricted row of PagingIETable.
func (t PagingIETable) EnhancedCoverageRestricted() PagingEnhancedCoverageRestrictedIEBinding {
	return PagingEnhancedCoverageRestrictedIEBinding{info: t.infoEnhancedCoverageRestricted(), codec: func() s00.EnhancedCoverageRestrictedValueCodec {
		sealed := s00.EnhancedCoverageRestrictedValueCodec{}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldPath(&sealed) = "EnhancedCoverageRestricted"
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EnhancedCoverageRestricted, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EnhancedCoverageRestricted
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EnhancedCoverageRestricted")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(251), raw)
			if err != nil {
				var empty s00.EnhancedCoverageRestricted
				return empty, runtime.WrapDecodePath(err, "EnhancedCoverageRestricted")
			}
			value, ok := decoded.AsEnhancedCoverageRestricted()
			if !ok {
				var empty s00.EnhancedCoverageRestricted
				return empty, fmt.Errorf("binding PagingIEs.id-EnhancedCoverageRestricted: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&sealed) = func(value s00.EnhancedCoverageRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(251), rowEnhancedCoverageRestricted: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldCapture(&sealed) = func(v s00.EnhancedCoverageRestricted, options aper.DecodeState) (s00.EnhancedCoverageRestricted, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEnhancedCoverageRestricted(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldCompare(&sealed) = func(v s00.EnhancedCoverageRestricted, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APEnhancedCoverageRestricted(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EnhancedCoverageRestricted"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.EnhancedCoverageRestricted) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(251), rowEnhancedCoverageRestricted: &value}
		}, get: func(value *PagingIEValue) (*s00.EnhancedCoverageRestricted, bool) {
			return value.AsEnhancedCoverageRestricted()
		}}
}
func (PagingIETable) infoCEModeBRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(271), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CE-ModeBRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-CE-ModeBRestricted"}}}
}

// CEModeBRestricted returns the typed binding for the CEModeBRestricted row of PagingIETable.
func (t PagingIETable) CEModeBRestricted() PagingCEModeBRestrictedIEBinding {
	return PagingCEModeBRestrictedIEBinding{info: t.infoCEModeBRestricted(), codec: func() s00.CEModeBRestrictedValueCodec {
		sealed := s00.CEModeBRestrictedValueCodec{}
		*s00.BridgeCEModeBRestrictedValueCodecFieldPath(&sealed) = "CEModeBRestricted"
		*s00.BridgeCEModeBRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CEModeBRestricted, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CEModeBRestricted
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CEModeBRestricted")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(271), raw)
			if err != nil {
				var empty s00.CEModeBRestricted
				return empty, runtime.WrapDecodePath(err, "CEModeBRestricted")
			}
			value, ok := decoded.AsCEModeBRestricted()
			if !ok {
				var empty s00.CEModeBRestricted
				return empty, fmt.Errorf("binding PagingIEs.id-CE-ModeBRestricted: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&sealed) = func(value s00.CEModeBRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(271), rowCEModeBRestricted: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldCapture(&sealed) = func(v s00.CEModeBRestricted, options aper.DecodeState) (s00.CEModeBRestricted, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCEModeBRestricted(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldCompare(&sealed) = func(v s00.CEModeBRestricted, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCEModeBRestricted(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CEModeBRestricted"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CEModeBRestricted) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(271), rowCEModeBRestricted: &value}
		}, get: func(value *PagingIEValue) (*s00.CEModeBRestricted, bool) { return value.AsCEModeBRestricted() }}
}
func (PagingIETable) infoDataSize() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(304), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "DataSize"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-DataSize"}}}
}

// DataSize returns the typed binding for the DataSize row of PagingIETable.
func (t PagingIETable) DataSize() PagingDataSizeIEBinding {
	return PagingDataSizeIEBinding{info: t.infoDataSize(), codec: func() s00.DataSizeValueCodec {
		sealed := s00.DataSizeValueCodec{}
		*s00.BridgeDataSizeValueCodecFieldPath(&sealed) = "DataSize"
		*s00.BridgeDataSizeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.DataSize, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.DataSize
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("DataSize")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(304), raw)
			if err != nil {
				var empty s00.DataSize
				return empty, runtime.WrapDecodePath(err, "DataSize")
			}
			value, ok := decoded.AsDataSize()
			if !ok {
				var empty s00.DataSize
				return empty, fmt.Errorf("binding PagingIEs.id-DataSize: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeDataSizeValueCodecFieldEncode(&sealed) = func(value s00.DataSize, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(304), rowDataSize: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeDataSizeValueCodecFieldCapture(&sealed) = func(v s00.DataSize, options aper.DecodeState) (s00.DataSize, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APDataSize(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeDataSizeValueCodecFieldCompare(&sealed) = func(v s00.DataSize, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APDataSize(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeDataSizeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DataSize"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.DataSize) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(304), rowDataSize: &value}
		}, get: func(value *PagingIEValue) (*s00.DataSize, bool) { return value.AsDataSize() }}
}
func (PagingIETable) infoWUSAssistanceInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(323), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "WUS-Assistance-Information"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-WUS-Assistance-Information"}}}
}

// WUSAssistanceInformation returns the typed binding for the WUSAssistanceInformation row of PagingIETable.
func (t PagingIETable) WUSAssistanceInformation() PagingWUSAssistanceInformationIEBinding {
	return PagingWUSAssistanceInformationIEBinding{info: t.infoWUSAssistanceInformation(), codec: WUSAssistanceInformationValueCodec{path: "WUSAssistanceInformation",
		decode: func(data []byte, options aper.DecodeState) (WUSAssistanceInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty WUSAssistanceInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("WUSAssistanceInformation")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(323), raw)
			if err != nil {
				var empty WUSAssistanceInformation
				return empty, runtime.WrapDecodePath(err, "WUSAssistanceInformation")
			}
			value, ok := decoded.AsWUSAssistanceInformation()
			if !ok {
				var empty WUSAssistanceInformation
				return empty, fmt.Errorf("binding PagingIEs.id-WUS-Assistance-Information: no selected value")
			}
			return *value, nil
		},
		encode: func(value WUSAssistanceInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(323), rowWUSAssistanceInformation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v WUSAssistanceInformation, options aper.DecodeState) (WUSAssistanceInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureS1APWUSAssistanceInformation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v WUSAssistanceInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APWUSAssistanceInformation(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WUSAssistanceInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value WUSAssistanceInformation) PagingIEValue {
		return PagingIEValue{id: s00.ProtocolIEID(323), rowWUSAssistanceInformation: &value}
	}, get: func(value *PagingIEValue) (*WUSAssistanceInformation, bool) {
		return value.AsWUSAssistanceInformation()
	}}
}
func (PagingIETable) infoNBIoTPagingDRX() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(324), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NB-IoT-PagingDRX"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-NB-IoT-PagingDRX"}}}
}

// NBIoTPagingDRX returns the typed binding for the NBIoTPagingDRX row of PagingIETable.
func (t PagingIETable) NBIoTPagingDRX() PagingNBIoTPagingDRXIEBinding {
	return PagingNBIoTPagingDRXIEBinding{info: t.infoNBIoTPagingDRX(), codec: func() s01.NBIoTPagingDRXValueCodec {
		sealed := s01.NBIoTPagingDRXValueCodec{}
		*s01.BridgeNBIoTPagingDRXValueCodecFieldPath(&sealed) = "NBIoTPagingDRX"
		*s01.BridgeNBIoTPagingDRXValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NBIoTPagingDRX, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.NBIoTPagingDRX
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NBIoTPagingDRX")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(324), raw)
			if err != nil {
				var empty s00.NBIoTPagingDRX
				return empty, runtime.WrapDecodePath(err, "NBIoTPagingDRX")
			}
			value, ok := decoded.AsNBIoTPagingDRX()
			if !ok {
				var empty s00.NBIoTPagingDRX
				return empty, fmt.Errorf("binding PagingIEs.id-NB-IoT-PagingDRX: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeNBIoTPagingDRXValueCodecFieldEncode(&sealed) = func(value s00.NBIoTPagingDRX, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(324), rowNBIoTPagingDRX: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeNBIoTPagingDRXValueCodecFieldCapture(&sealed) = func(v s00.NBIoTPagingDRX, options aper.DecodeState) (s00.NBIoTPagingDRX, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNBIoTPagingDRX(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeNBIoTPagingDRXValueCodecFieldCompare(&sealed) = func(v s00.NBIoTPagingDRX, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APNBIoTPagingDRX(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNBIoTPagingDRXValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NBIoTPagingDRX"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.NBIoTPagingDRX) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(324), rowNBIoTPagingDRX: &value}
		}, get: func(value *PagingIEValue) (*s00.NBIoTPagingDRX, bool) { return value.AsNBIoTPagingDRX() }}
}
func (PagingIETable) infoPagingCause() s00.FieldInfo {
	return s00.FieldInfo{Table: PagingIEs().ID(), ID: s00.ProtocolIEID(331), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PagingCause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "PagingIEs", Row: "id-PagingCause"}}}
}

// PagingCause returns the typed binding for the PagingCause row of PagingIETable.
func (t PagingIETable) PagingCause() PagingPagingCauseIEBinding {
	return PagingPagingCauseIEBinding{info: t.infoPagingCause(), codec: func() s01.PagingCauseValueCodec {
		sealed := s01.PagingCauseValueCodec{}
		*s01.BridgePagingCauseValueCodecFieldPath(&sealed) = "PagingCause"
		*s01.BridgePagingCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PagingCause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PagingCause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PagingCause")
			var zero PagingIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(331), raw)
			if err != nil {
				var empty s00.PagingCause
				return empty, runtime.WrapDecodePath(err, "PagingCause")
			}
			value, ok := decoded.AsPagingCause()
			if !ok {
				var empty s00.PagingCause
				return empty, fmt.Errorf("binding PagingIEs.id-PagingCause: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePagingCauseValueCodecFieldEncode(&sealed) = func(value s00.PagingCause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (PagingIEValue{id: s00.ProtocolIEID(331), rowPagingCause: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgePagingCauseValueCodecFieldCapture(&sealed) = func(v s00.PagingCause, options aper.DecodeState) (s00.PagingCause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPagingCause(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePagingCauseValueCodecFieldCompare(&sealed) = func(v s00.PagingCause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPagingCause(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s01.BridgePagingCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PagingCause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.PagingCause) PagingIEValue {
			return PagingIEValue{id: s00.ProtocolIEID(331), rowPagingCause: &value}
		}, get: func(value *PagingIEValue) (*s00.PagingCause, bool) { return value.AsPagingCause() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in PagingIETable.
func (t PagingIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (PagingIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return PagingIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(80):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-UEIdentityIndexValue requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(43):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-UEPagingID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(44):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-pagingDRX requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(109):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-CNDomain requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(46):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-TAIList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(128):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSG-IdList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(151):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-PagingPriority requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(198):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapabilityForPaging requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(211):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-AssistanceDataForPaging requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(227):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-Paging-eDRXInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(231):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-extended-UEIdentityIndexValue requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(239):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-NB-IoT-Paging-eDRXInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(244):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-NB-IoT-UEIdentityIndexValue requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(251):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-EnhancedCoverageRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(271):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-CE-ModeBRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(304):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-DataSize requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(323):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-WUS-Assistance-Information requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(324):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-NB-IoT-PagingDRX requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(331):
		return PagingIEField{}, aper.OperationError(fmt.Errorf("known IE id-PagingCause requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return PagingIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return PagingIEField{}, aper.OperationError(err, "Opaque")
		}
		return PagingIEField{Id: id, Criticality: criticality, Value: PagingIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// AssistanceDataForPagingCodec binds the complete APER value type.
func AssistanceDataForPagingCodec() s31.AssistanceDataForPagingValueCodec {
	return PagingIEs().AssistanceDataForPaging().Codec()
}

// CNDomainCodec binds the complete APER value type.
func CNDomainCodec() s00.CNDomainValueCodec { return PagingIEs().CNDomain().Codec() }

// DataSizeCodec binds the complete APER value type.
func DataSizeCodec() s00.DataSizeValueCodec { return PagingIEs().DataSize().Codec() }

// ExtendedUEIdentityIndexValueCodec binds the complete APER value type.
func ExtendedUEIdentityIndexValueCodec() s01.ExtendedUEIdentityIndexValueValueCodec {
	return PagingIEs().ExtendedUEIdentityIndexValue().Codec()
}

// NBIoTPagingDRXCodec binds the complete APER value type.
func NBIoTPagingDRXCodec() s01.NBIoTPagingDRXValueCodec { return PagingIEs().NBIoTPagingDRX().Codec() }

// NBIoTPagingEDRXInformationCodec binds the complete APER value type.
func NBIoTPagingEDRXInformationCodec() s23.NBIoTPagingEDRXInformationValueCodec {
	return PagingIEs().NBIoTPagingEDRXInformation().Codec()
}

// NBIoTUEIdentityIndexValueCodec binds the complete APER value type.
func NBIoTUEIdentityIndexValueCodec() s01.NBIoTUEIdentityIndexValueValueCodec {
	return PagingIEs().NBIoTUEIdentityIndexValue().Codec()
}

// PagingCauseCodec binds the complete APER value type.
func PagingCauseCodec() s01.PagingCauseValueCodec { return PagingIEs().PagingCause().Codec() }

// PagingEDRXInformationCodec binds the complete APER value type.
func PagingEDRXInformationCodec() s23.PagingEDRXInformationValueCodec {
	return PagingIEs().PagingEDRXInformation().Codec()
}

// PagingPriorityCodec binds the complete APER value type.
func PagingPriorityCodec() s01.PagingPriorityValueCodec { return PagingIEs().PagingPriority().Codec() }

// TAIListCodec binds the complete APER value type.
func TAIListCodec() s42.TAIListValueCodec { return PagingIEs().TAIList().Codec() }

// UEIdentityIndexValueCodec binds the complete APER value type.
func UEIdentityIndexValueCodec() s02.UEIdentityIndexValueValueCodec {
	return PagingIEs().UEIdentityIndexValue().Codec()
}

// UEPagingIDCodec binds the complete APER value type.
func UEPagingIDCodec() s36.UEPagingIDValueCodec { return PagingIEs().UEPagingID().Codec() }

// UERadioCapabilityForPagingCodec binds the complete APER value type.
func UERadioCapabilityForPagingCodec() s02.UERadioCapabilityForPagingValueCodec {
	return PagingIEs().UERadioCapabilityForPaging().Codec()
}

// WUSAssistanceInformationCodec binds the complete APER value type.
func WUSAssistanceInformationCodec() WUSAssistanceInformationValueCodec {
	return PagingIEs().WUSAssistanceInformation().Codec()
}
func BridgeValidateHandoverCommandBudget(v *s50.HandoverCommand, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverCommand")
	}
	rows := []s00.FieldInfo{s50.HandoverCommandIEs().MMEUES1APID().Info(), s50.HandoverCommandIEs().ENBUES1APID().Info(), s50.HandoverCommandIEs().HandoverType().Info(), s50.HandoverCommandIEs().NASSecurityParametersfromEUTRAN().Info(), s50.HandoverCommandIEs().ERABSubjecttoDataForwardingList().Info(), s50.HandoverCommandIEs().ERABtoReleaseListHOCmd().Info(), s50.HandoverCommandIEs().TargetToSourceTransparentContainer().Info(), s50.HandoverCommandIEs().TargetToSourceTransparentContainerSecondary().Info(), s50.HandoverCommandIEs().CriticalityDiagnostics().Info()}
	report := s50.BridgeHandoverCommandIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverCommand.protocolIEs", budget)
	BridgeWalkValidationHandoverCommand(v, &report, "HandoverCommand", true)
	return report, nil
}
func BridgeValidateHandoverPreparationFailureBudget(v *s29.HandoverPreparationFailure, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverPreparationFailure")
	}
	rows := []s00.FieldInfo{s26.HandoverPreparationFailureIEs().MMEUES1APID().Info(), s26.HandoverPreparationFailureIEs().ENBUES1APID().Info(), s26.HandoverPreparationFailureIEs().Cause().Info(), s26.HandoverPreparationFailureIEs().CriticalityDiagnostics().Info()}
	report := s34.BridgeHandoverPreparationFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverPreparationFailure.protocolIEs", budget)
	BridgeWalkValidationHandoverPreparationFailure(v, &report, "HandoverPreparationFailure", true)
	return report, nil
}
func BridgeValidateHandoverRequestAcknowledgeBudget(v *s49.HandoverRequestAcknowledge, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverRequestAcknowledge")
	}
	rows := []s00.FieldInfo{s49.HandoverRequestAcknowledgeIEs().MMEUES1APID().Info(), s49.HandoverRequestAcknowledgeIEs().ENBUES1APID().Info(), s49.HandoverRequestAcknowledgeIEs().ERABAdmittedList().Info(), s49.HandoverRequestAcknowledgeIEs().ERABFailedToSetupListHOReqAck().Info(), s49.HandoverRequestAcknowledgeIEs().TargetToSourceTransparentContainer().Info(), s49.HandoverRequestAcknowledgeIEs().CSGId().Info(), s49.HandoverRequestAcknowledgeIEs().CriticalityDiagnostics().Info(), s49.HandoverRequestAcknowledgeIEs().CellAccessMode().Info(), s49.HandoverRequestAcknowledgeIEs().CEModeBSupportIndicator().Info()}
	report := s49.BridgeHandoverRequestAcknowledgeIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverRequestAcknowledge.protocolIEs", budget)
	BridgeWalkValidationHandoverRequestAcknowledge(v, &report, "HandoverRequestAcknowledge", true)
	return report, nil
}
func BridgeValidateHandoverFailureBudget(v *s29.HandoverFailure, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverFailure")
	}
	rows := []s00.FieldInfo{s26.HandoverFailureIEs().MMEUES1APID().Info(), s26.HandoverFailureIEs().Cause().Info(), s26.HandoverFailureIEs().CriticalityDiagnostics().Info()}
	report := s34.BridgeHandoverFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverFailure.protocolIEs", budget)
	BridgeWalkValidationHandoverFailure(v, &report, "HandoverFailure", true)
	return report, nil
}
func BridgeValidateHandoverCancelBudget(v *s29.HandoverCancel, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverCancel")
	}
	rows := []s00.FieldInfo{s21.HandoverCancelIEs().MMEUES1APID().Info(), s21.HandoverCancelIEs().ENBUES1APID().Info(), s21.HandoverCancelIEs().Cause().Info()}
	report := s34.BridgeHandoverCancelIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverCancel.protocolIEs", budget)
	BridgeWalkValidationHandoverCancel(v, &report, "HandoverCancel", true)
	return report, nil
}
func BridgeValidateHandoverCancelAcknowledgeBudget(v *s29.HandoverCancelAcknowledge, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverCancelAcknowledge")
	}
	rows := []s00.FieldInfo{s26.HandoverCancelAcknowledgeIEs().MMEUES1APID().Info(), s26.HandoverCancelAcknowledgeIEs().ENBUES1APID().Info(), s26.HandoverCancelAcknowledgeIEs().CriticalityDiagnostics().Info()}
	report := s34.BridgeHandoverCancelAcknowledgeIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverCancelAcknowledge.protocolIEs", budget)
	BridgeWalkValidationHandoverCancelAcknowledge(v, &report, "HandoverCancelAcknowledge", true)
	return report, nil
}
func BridgeValidateDownlinkS1cdma2000tunnellingBudget(v *s50.DownlinkS1cdma2000tunnelling, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil DownlinkS1cdma2000tunnelling")
	}
	rows := []s00.FieldInfo{s50.DownlinkS1cdma2000tunnellingIEs().MMEUES1APID().Info(), s50.DownlinkS1cdma2000tunnellingIEs().ENBUES1APID().Info(), s50.DownlinkS1cdma2000tunnellingIEs().ERABSubjecttoDataForwardingList().Info(), s50.DownlinkS1cdma2000tunnellingIEs().Cdma2000HOStatus().Info(), s50.DownlinkS1cdma2000tunnellingIEs().Cdma2000RATType().Info(), s50.DownlinkS1cdma2000tunnellingIEs().Cdma2000PDU().Info()}
	report := s50.BridgeDownlinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "DownlinkS1cdma2000tunnelling.protocolIEs", budget)
	BridgeWalkValidationDownlinkS1cdma2000tunnelling(v, &report, "DownlinkS1cdma2000tunnelling", true)
	return report, nil
}
func BridgeValidateENBStatusTransferBudget(v *s28.ENBStatusTransfer, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBStatusTransfer")
	}
	rows := []s00.FieldInfo{s25.ENBStatusTransferIEs().MMEUES1APID().Info(), s25.ENBStatusTransferIEs().ENBUES1APID().Info(), s25.ENBStatusTransferIEs().ENBStatusTransferTransparentContainer().Info()}
	report := s32.BridgeENBStatusTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBStatusTransfer.protocolIEs", budget)
	BridgeWalkValidationENBStatusTransfer(v, &report, "ENBStatusTransfer", true)
	return report, nil
}
func BridgeValidateDeactivateTraceBudget(v *s18.DeactivateTrace, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil DeactivateTrace")
	}
	rows := []s00.FieldInfo{s09.DeactivateTraceIEs().MMEUES1APID().Info(), s09.DeactivateTraceIEs().ENBUES1APID().Info(), s09.DeactivateTraceIEs().EUTRANTraceID().Info()}
	report := s32.BridgeDeactivateTraceIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "DeactivateTrace.protocolIEs", budget)
	BridgeWalkValidationDeactivateTrace(v, &report, "DeactivateTrace", true)
	return report, nil
}
func BridgeValidateENBConfigurationUpdateAcknowledgeBudget(v *s28.ENBConfigurationUpdateAcknowledge, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBConfigurationUpdateAcknowledge")
	}
	rows := []s00.FieldInfo{s26.ENBConfigurationUpdateAcknowledgeIEs().CriticalityDiagnostics().Info()}
	report := s32.BridgeENBConfigurationUpdateAcknowledgeIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBConfigurationUpdateAcknowledge.protocolIEs", budget)
	BridgeWalkValidationENBConfigurationUpdateAcknowledge(v, &report, "ENBConfigurationUpdateAcknowledge", true)
	return report, nil
}
func BridgeValidateENBConfigurationUpdateFailureBudget(v *s28.ENBConfigurationUpdateFailure, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBConfigurationUpdateFailure")
	}
	rows := []s00.FieldInfo{s26.ENBConfigurationUpdateFailureIEs().Cause().Info(), s26.ENBConfigurationUpdateFailureIEs().TimeToWait().Info(), s26.ENBConfigurationUpdateFailureIEs().CriticalityDiagnostics().Info()}
	report := s32.BridgeENBConfigurationUpdateFailureIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBConfigurationUpdateFailure.protocolIEs", budget)
	BridgeWalkValidationENBConfigurationUpdateFailure(v, &report, "ENBConfigurationUpdateFailure", true)
	return report, nil
}
func BridgeValidateCellTrafficTraceBudget(v *s25.CellTrafficTrace, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil CellTrafficTrace")
	}
	rows := []s00.FieldInfo{s21.CellTrafficTraceIEs().MMEUES1APID().Info(), s21.CellTrafficTraceIEs().ENBUES1APID().Info(), s21.CellTrafficTraceIEs().EUTRANTraceID().Info(), s21.CellTrafficTraceIEs().EUTRANCGI().Info(), s21.CellTrafficTraceIEs().TraceCollectionEntityIPAddress().Info(), s21.CellTrafficTraceIEs().PrivacyIndicator().Info()}
	report := s32.BridgeCellTrafficTraceIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "CellTrafficTrace.protocolIEs", budget)
	BridgeWalkValidationCellTrafficTrace(v, &report, "CellTrafficTrace", true)
	return report, nil
}
func BridgeValidateDownlinkUEAssociatedLPPaTransportBudget(v *s18.DownlinkUEAssociatedLPPaTransport, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil DownlinkUEAssociatedLPPaTransport")
	}
	rows := []s00.FieldInfo{s09.DownlinkUEAssociatedLPPaTransportIEs().MMEUES1APID().Info(), s09.DownlinkUEAssociatedLPPaTransportIEs().ENBUES1APID().Info(), s09.DownlinkUEAssociatedLPPaTransportIEs().RoutingID().Info(), s09.DownlinkUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
	report := s32.BridgeDownlinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "DownlinkUEAssociatedLPPaTransport.protocolIEs", budget)
	BridgeWalkValidationDownlinkUEAssociatedLPPaTransport(v, &report, "DownlinkUEAssociatedLPPaTransport", true)
	return report, nil
}
func BridgeValidateDownlinkNonUEAssociatedLPPaTransportBudget(v *s18.DownlinkNonUEAssociatedLPPaTransport, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil DownlinkNonUEAssociatedLPPaTransport")
	}
	rows := []s00.FieldInfo{s09.DownlinkNonUEAssociatedLPPaTransportIEs().RoutingID().Info(), s09.DownlinkNonUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
	report := s32.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "DownlinkNonUEAssociatedLPPaTransport.protocolIEs", budget)
	BridgeWalkValidationDownlinkNonUEAssociatedLPPaTransport(v, &report, "DownlinkNonUEAssociatedLPPaTransport", true)
	return report, nil
}
func BridgeValidateERABModificationConfirmBudget(v *s49.ERABModificationConfirm, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ERABModificationConfirm")
	}
	rows := []s00.FieldInfo{s49.ERABModificationConfirmIEs().MMEUES1APID().Info(), s49.ERABModificationConfirmIEs().ENBUES1APID().Info(), s49.ERABModificationConfirmIEs().ERABModifyListBearerModConf().Info(), s49.ERABModificationConfirmIEs().ERABFailedToModifyListBearerModConf().Info(), s49.ERABModificationConfirmIEs().ERABToBeReleasedListBearerModConf().Info(), s49.ERABModificationConfirmIEs().CriticalityDiagnostics().Info(), s49.ERABModificationConfirmIEs().CSGMembershipStatus().Info()}
	report := s49.BridgeERABModificationConfirmIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ERABModificationConfirm.protocolIEs", budget)
	BridgeWalkValidationERABModificationConfirm(v, &report, "ERABModificationConfirm", true)
	return report, nil
}
func BridgeValidateHandoverSuccessBudget(v *s21.HandoverSuccess, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverSuccess")
	}
	rows := []s00.FieldInfo{s11.HandoverSuccessIEs().MMEUES1APID().Info(), s11.HandoverSuccessIEs().ENBUES1APID().Info()}
	report := s34.BridgeHandoverSuccessIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverSuccess.protocolIEs", budget)
	BridgeWalkValidationHandoverSuccess(v, &report, "HandoverSuccess", true)
	return report, nil
}
func BridgeValidateENBEarlyStatusTransferBudget(v *s47.ENBEarlyStatusTransfer, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ENBEarlyStatusTransfer")
	}
	rows := []s00.FieldInfo{s47.ENBEarlyStatusTransferIEs().MMEUES1APID().Info(), s47.ENBEarlyStatusTransferIEs().ENBUES1APID().Info(), s47.ENBEarlyStatusTransferIEs().ENBEarlyStatusTransferTransparentContainer().Info()}
	report := s47.BridgeENBEarlyStatusTransferIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "ENBEarlyStatusTransfer.protocolIEs", budget)
	BridgeWalkValidationENBEarlyStatusTransfer(v, &report, "ENBEarlyStatusTransfer", true)
	return report, nil
}
func ValidateHandoverCommand(v *s50.HandoverCommand, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "HandoverCommand")
	}
	report, err := BridgeValidateHandoverCommandBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s50.BridgeHandoverCommandMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverCommand")
}
func ValidateHandoverPreparationFailure(v *s29.HandoverPreparationFailure, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "HandoverPreparationFailure")
	}
	report, err := BridgeValidateHandoverPreparationFailureBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s29.BridgeHandoverPreparationFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverPreparationFailure")
}
func ValidateHandoverRequestAcknowledge(v *s49.HandoverRequestAcknowledge, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "HandoverRequestAcknowledge")
	}
	report, err := BridgeValidateHandoverRequestAcknowledgeBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s49.BridgeHandoverRequestAcknowledgeMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverRequestAcknowledge")
}
func ValidateHandoverFailure(v *s29.HandoverFailure, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "HandoverFailure")
	}
	report, err := BridgeValidateHandoverFailureBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s29.BridgeHandoverFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverFailure")
}
func ValidateHandoverCancel(v *s29.HandoverCancel, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "HandoverCancel")
	}
	report, err := BridgeValidateHandoverCancelBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s29.BridgeHandoverCancelMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverCancel")
}
func ValidateHandoverCancelAcknowledge(v *s29.HandoverCancelAcknowledge, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "HandoverCancelAcknowledge")
	}
	report, err := BridgeValidateHandoverCancelAcknowledgeBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s29.BridgeHandoverCancelAcknowledgeMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverCancelAcknowledge")
}
func ValidateDownlinkS1cdma2000tunnelling(v *s50.DownlinkS1cdma2000tunnelling, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "DownlinkS1cdma2000tunnelling")
	}
	report, err := BridgeValidateDownlinkS1cdma2000tunnellingBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s50.BridgeDownlinkS1cdma2000tunnellingMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "DownlinkS1cdma2000tunnelling")
}
func ValidateENBStatusTransfer(v *s28.ENBStatusTransfer, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ENBStatusTransfer")
	}
	report, err := BridgeValidateENBStatusTransferBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s28.BridgeENBStatusTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBStatusTransfer")
}
func ValidateDeactivateTrace(v *s18.DeactivateTrace, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "DeactivateTrace")
	}
	report, err := BridgeValidateDeactivateTraceBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s18.BridgeDeactivateTraceMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "DeactivateTrace")
}
func ValidateENBConfigurationUpdateAcknowledge(v *s28.ENBConfigurationUpdateAcknowledge, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
	}
	report, err := BridgeValidateENBConfigurationUpdateAcknowledgeBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s28.BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
}
func ValidateENBConfigurationUpdateFailure(v *s28.ENBConfigurationUpdateFailure, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ENBConfigurationUpdateFailure")
	}
	report, err := BridgeValidateENBConfigurationUpdateFailureBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s28.BridgeENBConfigurationUpdateFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBConfigurationUpdateFailure")
}
func ValidateCellTrafficTrace(v *s25.CellTrafficTrace, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "CellTrafficTrace")
	}
	report, err := BridgeValidateCellTrafficTraceBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s25.BridgeCellTrafficTraceMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "CellTrafficTrace")
}
func ValidateDownlinkUEAssociatedLPPaTransport(v *s18.DownlinkUEAssociatedLPPaTransport, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "DownlinkUEAssociatedLPPaTransport")
	}
	report, err := BridgeValidateDownlinkUEAssociatedLPPaTransportBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s18.BridgeDownlinkUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "DownlinkUEAssociatedLPPaTransport")
}
func ValidateDownlinkNonUEAssociatedLPPaTransport(v *s18.DownlinkNonUEAssociatedLPPaTransport, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "DownlinkNonUEAssociatedLPPaTransport")
	}
	report, err := BridgeValidateDownlinkNonUEAssociatedLPPaTransportBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s18.BridgeDownlinkNonUEAssociatedLPPaTransportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "DownlinkNonUEAssociatedLPPaTransport")
}
func ValidateERABModificationConfirm(v *s49.ERABModificationConfirm, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ERABModificationConfirm")
	}
	report, err := BridgeValidateERABModificationConfirmBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s49.BridgeERABModificationConfirmMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ERABModificationConfirm")
}
func ValidateHandoverSuccess(v *s21.HandoverSuccess, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "HandoverSuccess")
	}
	report, err := BridgeValidateHandoverSuccessBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s21.BridgeHandoverSuccessMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverSuccess")
}
func ValidateENBEarlyStatusTransfer(v *s47.ENBEarlyStatusTransfer, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "ENBEarlyStatusTransfer")
	}
	report, err := BridgeValidateENBEarlyStatusTransferBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s47.BridgeENBEarlyStatusTransferMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ENBEarlyStatusTransfer")
}
func BridgeWalkValidationActivatedCellsList(v *s16.ActivatedCellsList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationActivatedCellsListItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationActivatedCellsListItem(v *s16.ActivatedCellsListItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationAdditionalGUTI(v *s21.AdditionalGUTI, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationGUMMEI(&v.GUMMEI, report, path+".gUMMEI", false)
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
				s30.BridgeMergeNestedValidation(report, s31.BridgeAdditionalGUTIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationAllocationAndRetentionPriority(v *s16.AllocationAndRetentionPriority, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s31.BridgeAllocationAndRetentionPriorityExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationAssistanceDataForCECapableUEs(v *s20.AssistanceDataForCECapableUEs, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationCellIdentifierAndCELevelForCECapableUEs(&v.CellIdentifierAndCELevelForCECapableUEs, report, path+".cellIdentifierAndCELevelForCECapableUEs", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s34.BridgeInformationForCECapableUEsExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationBPLMNs(v *s00.BPLMNs, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationBearersSubjectToDLDiscardingItem(v *s17.BearersSubjectToDLDiscardingItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationDLDiscarding(&v.DLDiscarding, report, path+".dL-Discarding", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s31.BridgeBearersSubjectToDLDiscardingItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationBearersSubjectToDLDiscardingList(v *s17.BearersSubjectToDLDiscardingList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s17.BearersSubjectToDLDiscardingItemIEs().BearersSubjectToDLDiscardingItem().Info()}
		s30.BridgeMergeNestedValidation(report, s31.BridgeBearersSubjectToDLDiscardingItemIEValueValidateS1APIEContainer(s17.BearersSubjectToDLDiscardingItemIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s17.BearersSubjectToDLDiscardingItemIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(351):
				if value, ok := fields[i].Value.AsBearersSubjectToDLDiscardingItem(); ok {
					BridgeWalkValidationBearersSubjectToDLDiscardingItem(value, report, fmt.Sprintf("%s[%d]{id=351}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationBearersSubjectToEarlyStatusTransferItem(v *s17.BearersSubjectToEarlyStatusTransferItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationDLCOUNTPDCPSNlength(&v.DLCOUNTPDCPSNlength, report, path+".dLCOUNT-PDCP-SNlength", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s31.BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationBearersSubjectToEarlyStatusTransferList(v *s17.BearersSubjectToEarlyStatusTransferList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s17.BearersSubjectToEarlyStatusTransferItemIEs().BearersSubjectToEarlyStatusTransferItem().Info()}
		s30.BridgeMergeNestedValidation(report, s31.BridgeBearersSubjectToEarlyStatusTransferItemIEValueValidateS1APIEContainer(s17.BearersSubjectToEarlyStatusTransferItemIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s17.BearersSubjectToEarlyStatusTransferItemIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(322):
				if value, ok := fields[i].Value.AsBearersSubjectToEarlyStatusTransferItem(); ok {
					BridgeWalkValidationBearersSubjectToEarlyStatusTransferItem(value, report, fmt.Sprintf("%s[%d]{id=322}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationBearersSubjectToStatusTransferItem(v *s25.BearersSubjectToStatusTransferItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationCOUNTvalue(&v.ULCOUNTvalue, report, path+".uL-COUNTvalue", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationCOUNTvalue(&v.DLCOUNTvalue, report, path+".dL-COUNTvalue", false)
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
				rows := []s00.FieldInfo{s00.FieldInfo(s17.BearersSubjectToStatusTransferItemExtIEs().ULCOUNTValueExtended().Info()), s00.FieldInfo(s17.BearersSubjectToStatusTransferItemExtIEs().DLCOUNTValueExtended().Info()), s00.FieldInfo(s17.BearersSubjectToStatusTransferItemExtIEs().ReceiveStatusOfULPDCPSDUsExtended().Info()), s00.FieldInfo(s17.BearersSubjectToStatusTransferItemExtIEs().ULCOUNTValuePDCPSNlength18().Info()), s00.FieldInfo(s17.BearersSubjectToStatusTransferItemExtIEs().DLCOUNTValuePDCPSNlength18().Info()), s00.FieldInfo(s17.BearersSubjectToStatusTransferItemExtIEs().ReceiveStatusOfULPDCPSDUsPDCPSNlength18().Info())}
				s30.BridgeMergeNestedValidation(report, s31.BridgeBearersSubjectToStatusTransferItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(179):
					if value, ok := fields[i].ExtensionValue.AsULCOUNTValueExtended(); ok {
						BridgeWalkValidationCOUNTValueExtended(value, report, fmt.Sprintf("%s[%d]{id=179}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(180):
					if value, ok := fields[i].ExtensionValue.AsDLCOUNTValueExtended(); ok {
						BridgeWalkValidationCOUNTValueExtended(value, report, fmt.Sprintf("%s[%d]{id=180}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(217):
					if value, ok := fields[i].ExtensionValue.AsULCOUNTValuePDCPSNlength18(); ok {
						BridgeWalkValidationCOUNTvaluePDCPSNlength18(value, report, fmt.Sprintf("%s[%d]{id=217}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(218):
					if value, ok := fields[i].ExtensionValue.AsDLCOUNTValuePDCPSNlength18(); ok {
						BridgeWalkValidationCOUNTvaluePDCPSNlength18(value, report, fmt.Sprintf("%s[%d]{id=218}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationBearersSubjectToStatusTransferList(v *s25.BearersSubjectToStatusTransferList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s25.BearersSubjectToStatusTransferItemIEs().BearersSubjectToStatusTransferItem().Info()}
		s30.BridgeMergeNestedValidation(report, s31.BridgeBearersSubjectToStatusTransferItemIEValueValidateS1APIEContainer(s25.BearersSubjectToStatusTransferItemIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s25.BearersSubjectToStatusTransferItemIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(89):
				if value, ok := fields[i].Value.AsBearersSubjectToStatusTransferItem(); ok {
					BridgeWalkValidationBearersSubjectToStatusTransferItem(value, report, fmt.Sprintf("%s[%d]{id=89}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationBluetoothMeasConfigNameList(v *s00.BluetoothMeasConfigNameList, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationBluetoothMeasurementConfiguration(v *s16.BluetoothMeasurementConfiguration, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.BluetoothMeasConfigNameList != nil {
		BridgeWalkValidationBluetoothMeasConfigNameList(&v.BluetoothMeasConfigNameList, report, path+".bluetoothMeasConfigNameList", false)
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
				s30.BridgeMergeNestedValidation(report, s31.BridgeBluetoothMeasurementConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCGI(v *s16.CGI, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s31.BridgeCGIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCNTypeRestrictions(v *s16.CNTypeRestrictions, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationCNTypeRestrictionsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCNTypeRestrictionsItem(v *s16.CNTypeRestrictionsItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s31.BridgeCNTypeRestrictionsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCOUNTValueExtended(v *s16.COUNTValueExtended, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s31.BridgeCOUNTValueExtendedExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCOUNTvalue(v *s16.COUNTvalue, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s31.BridgeCOUNTvalueExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCOUNTvaluePDCPSNlength18(v *s16.COUNTvaluePDCPSNlength18, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s31.BridgeCOUNTvaluePDCPSNlength18ExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCSGIdList(v *s17.CSGIdList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationCSGIdListItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCSGIdListItem(v *s17.CSGIdListItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s31.BridgeCSGIdListItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCSGMembershipInfo(v *s17.CSGMembershipInfo, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s31.BridgeCSGMembershipInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCancelledCellinEAI(v *s20.CancelledCellinEAI, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationCancelledCellinEAIItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCancelledCellinEAIItem(v *s20.CancelledCellinEAIItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.ECGI, report, path+".eCGI", false)
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
				s30.BridgeMergeNestedValidation(report, s31.BridgeCancelledCellinEAIItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCancelledCellinTAI(v *s20.CancelledCellinTAI, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationCancelledCellinTAIItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCancelledCellinTAIItem(v *s20.CancelledCellinTAIItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.ECGI, report, path+".eCGI", false)
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
				s30.BridgeMergeNestedValidation(report, s31.BridgeCancelledCellinTAIItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCandidateCellList(v *s21.CandidateCellList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationIRATCellID(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCandidatePCI(v *s17.CandidatePCI, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationCandidatePCIList(v *s17.CandidatePCIList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationCandidatePCI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCause(v *s17.Cause, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationCdma2000OneXSRVCCInfo(v *s17.Cdma2000OneXSRVCCInfo, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s31.BridgeCdma2000OneXSRVCCInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCellActivationRequest(v *s26.CellActivationRequest, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationCellsToActivateList(&v.CellsToActivateList, report, path+".cellsToActivateList", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCellActivationResponse(v *s25.CellActivationResponse, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationActivatedCellsList(&v.ActivatedCellsList, report, path+".activatedCellsList", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCellBasedMDT(v *s25.CellBasedMDT, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationCellIdListforMDT(&v.CellIdListforMDT, report, path+".cellIdListforMDT", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s31.BridgeCellBasedMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCellBasedQMC(v *s25.CellBasedQMC, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationCellIdListforQMC(&v.CellIdListforQMC, report, path+".cellIdListforQMC", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s32.BridgeCellBasedQMCExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCellIDBroadcast(v *s20.CellIDBroadcast, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationCellIDBroadcastItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCellIDBroadcastItem(v *s20.CellIDBroadcastItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.ECGI, report, path+".eCGI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s32.BridgeCellIDBroadcastItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCellIDCancelled(v *s20.CellIDCancelled, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationCellIDCancelledItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCellIDCancelledItem(v *s20.CellIDCancelledItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.ECGI, report, path+".eCGI", false)
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
				s30.BridgeMergeNestedValidation(report, s32.BridgeCellIDCancelledItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCellIdListforMDT(v *s20.CellIdListforMDT, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationEUTRANCGI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCellIdListforQMC(v *s20.CellIdListforQMC, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationEUTRANCGI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCellIdentifierAndCELevelForCECapableUEs(v *s20.CellIdentifierAndCELevelForCECapableUEs, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.GlobalCellID, report, path+".global-Cell-ID", false)
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
				s30.BridgeMergeNestedValidation(report, s32.BridgeCellIdentifierAndCELevelForCECapableUEsExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCellLoadReportingResponse(v *s21.CellLoadReportingResponse, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.CellLoadReportingResponseChoiceEUTRAN && v.EUTRAN != nil {
		BridgeWalkValidationEUTRANcellLoadReportingResponse(v.EUTRAN, report, path+".eUTRAN", false)
	}
	if v.Choice == s00.CellLoadReportingResponseChoiceEHRPD && v.EHRPD != nil {
		BridgeWalkValidationEHRPDSectorLoadReportingResponse(v.EHRPD, report, path+".eHRPD", false)
	}
}
func BridgeWalkValidationCellTrafficTrace(v *s25.CellTrafficTrace, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s21.CellTrafficTraceIEs().MMEUES1APID().Info(), s21.CellTrafficTraceIEs().ENBUES1APID().Info(), s21.CellTrafficTraceIEs().EUTRANTraceID().Info(), s21.CellTrafficTraceIEs().EUTRANCGI().Info(), s21.CellTrafficTraceIEs().TraceCollectionEntityIPAddress().Info(), s21.CellTrafficTraceIEs().PrivacyIndicator().Info()}
			s30.BridgeMergeNestedValidation(report, s32.BridgeCellTrafficTraceIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(100):
				if value, ok := fields[i].Value.AsEUTRANCGI(); ok {
					BridgeWalkValidationEUTRANCGI(value, report, fmt.Sprintf("%s[%d]{id=100}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCellType(v *s17.CellType, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s32.BridgeCellTypeExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCellsToActivateList(v *s17.CellsToActivateList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationCellsToActivateListItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCellsToActivateListItem(v *s17.CellsToActivateListItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationCompletedCellinEAI(v *s20.CompletedCellinEAI, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationCompletedCellinEAIItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCompletedCellinEAIItem(v *s20.CompletedCellinEAIItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.ECGI, report, path+".eCGI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s32.BridgeCompletedCellinEAIItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCompletedCellinTAI(v *s20.CompletedCellinTAI, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationCompletedCellinTAIItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCompletedCellinTAIItem(v *s20.CompletedCellinTAIItem, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEUTRANCGI(&v.ECGI, report, path+".eCGI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s32.BridgeCompletedCellinTAIItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCriticalityDiagnostics(v *s26.CriticalityDiagnostics, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.IEsCriticalityDiagnostics != nil {
		BridgeWalkValidationCriticalityDiagnosticsIEList(&v.IEsCriticalityDiagnostics, report, path+".iEsCriticalityDiagnostics", false)
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
				s30.BridgeMergeNestedValidation(report, s32.BridgeCriticalityDiagnosticsExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCriticalityDiagnosticsIEItem(v *s17.CriticalityDiagnosticsIEItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s32.BridgeCriticalityDiagnosticsIEItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationCriticalityDiagnosticsIEList(v *s17.CriticalityDiagnosticsIEList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationCriticalityDiagnosticsIEItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationDAPSRequestInfo(v *s17.DAPSRequestInfo, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s32.BridgeDAPSRequestInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationDAPSResponseInfo(v *s17.DAPSResponseInfo, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s32.BridgeDAPSResponseInfoExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationDAPSResponseInfoItem(v *s17.DAPSResponseInfoItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationDAPSResponseInfo(&v.DAPSResponseInfo, report, path+".dAPSResponseInfo", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s32.BridgeDAPSResponseInfoItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationDAPSResponseInfoList(v *s17.DAPSResponseInfoList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s17.DAPSResponseInfoListIEs().DAPSResponseInfoItem().Info()}
		s30.BridgeMergeNestedValidation(report, s32.BridgeDAPSResponseInfoListIEValueValidateS1APIEContainer(s17.DAPSResponseInfoListIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s17.DAPSResponseInfoListIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(319):
				if value, ok := fields[i].Value.AsDAPSResponseInfoItem(); ok {
					BridgeWalkValidationDAPSResponseInfoItem(value, report, fmt.Sprintf("%s[%d]{id=319}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationDLCOUNTPDCPSNlength(v *s17.DLCOUNTPDCPSNlength, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength12 && v.DLCOUNTValuePDCPSNlength12 != nil {
		BridgeWalkValidationCOUNTvalue(v.DLCOUNTValuePDCPSNlength12, report, path+".dLCOUNTValuePDCP-SNlength12", false)
	}
	if v.Choice == s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength15 && v.DLCOUNTValuePDCPSNlength15 != nil {
		BridgeWalkValidationCOUNTValueExtended(v.DLCOUNTValuePDCPSNlength15, report, path+".dLCOUNTValuePDCP-SNlength15", false)
	}
	if v.Choice == s00.DLCOUNTPDCPSNlengthChoiceDLCOUNTValuePDCPSNlength18 && v.DLCOUNTValuePDCPSNlength18 != nil {
		BridgeWalkValidationCOUNTvaluePDCPSNlength18(v.DLCOUNTValuePDCPSNlength18, report, path+".dLCOUNTValuePDCP-SNlength18", false)
	}
}
func BridgeWalkValidationDLCPSecurityInformation(v *s17.DLCPSecurityInformation, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s32.BridgeDLCPSecurityInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationDLDiscarding(v *s17.DLDiscarding, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength12 && v.DiscardDLCOUNTValuePDCPSNlength12 != nil {
		BridgeWalkValidationCOUNTvalue(v.DiscardDLCOUNTValuePDCPSNlength12, report, path+".discardDLCOUNTValuePDCP-SNlength12", false)
	}
	if v.Choice == s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength15 && v.DiscardDLCOUNTValuePDCPSNlength15 != nil {
		BridgeWalkValidationCOUNTValueExtended(v.DiscardDLCOUNTValuePDCPSNlength15, report, path+".discardDLCOUNTValuePDCP-SNlength15", false)
	}
	if v.Choice == s00.DLDiscardingChoiceDiscardDLCOUNTValuePDCPSNlength18 && v.DiscardDLCOUNTValuePDCPSNlength18 != nil {
		BridgeWalkValidationCOUNTvaluePDCPSNlength18(v.DiscardDLCOUNTValuePDCPSNlength18, report, path+".discardDLCOUNTValuePDCP-SNlength18", false)
	}
}
func BridgeWalkValidationDeactivateTrace(v *s18.DeactivateTrace, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s09.DeactivateTraceIEs().MMEUES1APID().Info(), s09.DeactivateTraceIEs().ENBUES1APID().Info(), s09.DeactivateTraceIEs().EUTRANTraceID().Info()}
			s30.BridgeMergeNestedValidation(report, s32.BridgeDeactivateTraceIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationDownlinkNonUEAssociatedLPPaTransport(v *s18.DownlinkNonUEAssociatedLPPaTransport, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s09.DownlinkNonUEAssociatedLPPaTransportIEs().RoutingID().Info(), s09.DownlinkNonUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
			s30.BridgeMergeNestedValidation(report, s32.BridgeDownlinkNonUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationDownlinkS1cdma2000tunnelling(v *s50.DownlinkS1cdma2000tunnelling, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s50.DownlinkS1cdma2000tunnellingIEs().MMEUES1APID().Info(), s50.DownlinkS1cdma2000tunnellingIEs().ENBUES1APID().Info(), s50.DownlinkS1cdma2000tunnellingIEs().ERABSubjecttoDataForwardingList().Info(), s50.DownlinkS1cdma2000tunnellingIEs().Cdma2000HOStatus().Info(), s50.DownlinkS1cdma2000tunnellingIEs().Cdma2000RATType().Info(), s50.DownlinkS1cdma2000tunnellingIEs().Cdma2000PDU().Info()}
			s30.BridgeMergeNestedValidation(report, s50.BridgeDownlinkS1cdma2000tunnellingIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(12):
				if value, ok := fields[i].Value.AsERABSubjecttoDataForwardingList(); ok {
					BridgeWalkValidationERABSubjecttoDataForwardingList(value, report, fmt.Sprintf("%s[%d]{id=12}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationDownlinkUEAssociatedLPPaTransport(v *s18.DownlinkUEAssociatedLPPaTransport, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s09.DownlinkUEAssociatedLPPaTransportIEs().MMEUES1APID().Info(), s09.DownlinkUEAssociatedLPPaTransportIEs().ENBUES1APID().Info(), s09.DownlinkUEAssociatedLPPaTransportIEs().RoutingID().Info(), s09.DownlinkUEAssociatedLPPaTransportIEs().LPPaPDU().Info()}
			s30.BridgeMergeNestedValidation(report, s32.BridgeDownlinkUEAssociatedLPPaTransportIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationECGIList(v *s20.ECGIList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationEUTRANCGI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationECGIListForRestart(v *s20.ECGIListForRestart, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationEUTRANCGI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationEHRPDCompositeAvailableCapacity(v *s18.EHRPDCompositeAvailableCapacity, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationEHRPDMultiSectorLoadReportingResponseItem(v *s18.EHRPDMultiSectorLoadReportingResponseItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationEHRPDSectorLoadReportingResponse(&v.EHRPDSectorLoadReportingResponse, report, path+".eHRPDSectorLoadReportingResponse", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEHRPDSectorLoadReportingResponse(v *s18.EHRPDSectorLoadReportingResponse, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationEHRPDCompositeAvailableCapacity(&v.DLEHRPDCompositeAvailableCapacity, report, path+".dL-EHRPD-CompositeAvailableCapacity", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationEHRPDCompositeAvailableCapacity(&v.ULEHRPDCompositeAvailableCapacity, report, path+".uL-EHRPD-CompositeAvailableCapacity", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBConfigurationUpdateAcknowledge(v *s28.ENBConfigurationUpdateAcknowledge, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s26.ENBConfigurationUpdateAcknowledgeIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s32.BridgeENBConfigurationUpdateAcknowledgeIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBConfigurationUpdateFailure(v *s28.ENBConfigurationUpdateFailure, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s26.ENBConfigurationUpdateFailureIEs().Cause().Info(), s26.ENBConfigurationUpdateFailureIEs().TimeToWait().Info(), s26.ENBConfigurationUpdateFailureIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s32.BridgeENBConfigurationUpdateFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBEarlyStatusTransfer(v *s47.ENBEarlyStatusTransfer, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s47.ENBEarlyStatusTransferIEs().MMEUES1APID().Info(), s47.ENBEarlyStatusTransferIEs().ENBUES1APID().Info(), s47.ENBEarlyStatusTransferIEs().ENBEarlyStatusTransferTransparentContainer().Info()}
			s30.BridgeMergeNestedValidation(report, s47.BridgeENBEarlyStatusTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(321):
				if value, ok := fields[i].Value.AsENBEarlyStatusTransferTransparentContainer(); ok {
					BridgeWalkValidationENBEarlyStatusTransferTransparentContainer(value, report, fmt.Sprintf("%s[%d]{id=321}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBEarlyStatusTransferTransparentContainer(v *s47.ENBEarlyStatusTransferTransparentContainer, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationBearersSubjectToEarlyStatusTransferList(&v.BearersSubjectToEarlyStatusTransferList, report, path+".bearers-SubjectToEarlyStatusTransferList", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s47.ENBEarlyStatusTransferTransparentContainerExtIEs().BearersSubjectToDLDiscardingList().Info())}
				s30.BridgeMergeNestedValidation(report, s47.BridgeENBEarlyStatusTransferTransparentContainerExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(352):
					if value, ok := fields[i].ExtensionValue.AsBearersSubjectToDLDiscardingList(); ok {
						BridgeWalkValidationBearersSubjectToDLDiscardingList(value, report, fmt.Sprintf("%s[%d]{id=352}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBID(v *s18.ENBID, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationENBIndirectX2TransportLayerAddresses(v *s00.ENBIndirectX2TransportLayerAddresses, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationENBStatusTransfer(v *s28.ENBStatusTransfer, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s25.ENBStatusTransferIEs().MMEUES1APID().Info(), s25.ENBStatusTransferIEs().ENBUES1APID().Info(), s25.ENBStatusTransferIEs().ENBStatusTransferTransparentContainer().Info()}
			s30.BridgeMergeNestedValidation(report, s32.BridgeENBStatusTransferIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(90):
				if value, ok := fields[i].Value.AsENBStatusTransferTransparentContainer(); ok {
					BridgeWalkValidationENBStatusTransferTransparentContainer(value, report, fmt.Sprintf("%s[%d]{id=90}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationENBStatusTransferTransparentContainer(v *s25.ENBStatusTransferTransparentContainer, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationBearersSubjectToStatusTransferList(&v.BearersSubjectToStatusTransferList, report, path+".bearers-SubjectToStatusTransferList", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s32.BridgeENBStatusTransferTransparentContainerExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationENBX2ExtTLA(v *s18.ENBX2ExtTLA, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.GTPTLAa != nil {
		BridgeWalkValidationENBX2GTPTLAs(&v.GTPTLAa, report, path+".gTPTLAa", false)
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
				s30.BridgeMergeNestedValidation(report, s32.BridgeENBX2ExtTLAExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationENBX2ExtTLAs(v *s18.ENBX2ExtTLAs, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationENBX2ExtTLA(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationENBX2GTPTLAs(v *s00.ENBX2GTPTLAs, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationENBX2TLAs(v *s00.ENBX2TLAs, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationEPLMNs(v *s00.EPLMNs, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationERABAdmittedItem(v *s18.ERABAdmittedItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s32.BridgeERABAdmittedItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABAdmittedList(v *s18.ERABAdmittedList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s18.ERABAdmittedItemIEs().ERABAdmittedItem().Info()}
		s30.BridgeMergeNestedValidation(report, s32.BridgeERABAdmittedItemIEValueValidateS1APIEContainer(s18.ERABAdmittedItemIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s18.ERABAdmittedItemIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(20):
				if value, ok := fields[i].Value.AsERABAdmittedItem(); ok {
					BridgeWalkValidationERABAdmittedItem(value, report, fmt.Sprintf("%s[%d]{id=20}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABDataForwardingItem(v *s18.ERABDataForwardingItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s32.BridgeERABDataForwardingItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABFailedToResumeItemResumeReq(v *s18.ERABFailedToResumeItemResumeReq, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationCause(&v.Cause, report, path+".cause", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABFailedToResumeItemResumeReqExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABFailedToResumeItemResumeRes(v *s18.ERABFailedToResumeItemResumeRes, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationCause(&v.Cause, report, path+".cause", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABFailedToResumeItemResumeResExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABFailedToResumeListResumeReq(v *s18.ERABFailedToResumeListResumeReq, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s18.ERABFailedToResumeItemResumeReqIEs().ERABFailedToResumeItemResumeReq().Info()}
		s30.BridgeMergeNestedValidation(report, s33.BridgeERABFailedToResumeItemResumeReqIEValueValidateS1APIEContainer(s18.ERABFailedToResumeItemResumeReqIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s18.ERABFailedToResumeItemResumeReqIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(236):
				if value, ok := fields[i].Value.AsERABFailedToResumeItemResumeReq(); ok {
					BridgeWalkValidationERABFailedToResumeItemResumeReq(value, report, fmt.Sprintf("%s[%d]{id=236}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABFailedToResumeListResumeRes(v *s18.ERABFailedToResumeListResumeRes, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s18.ERABFailedToResumeItemResumeResIEs().ERABFailedToResumeItemResumeRes().Info()}
		s30.BridgeMergeNestedValidation(report, s33.BridgeERABFailedToResumeItemResumeResIEValueValidateS1APIEContainer(s18.ERABFailedToResumeItemResumeResIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s18.ERABFailedToResumeItemResumeResIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(238):
				if value, ok := fields[i].Value.AsERABFailedToResumeItemResumeRes(); ok {
					BridgeWalkValidationERABFailedToResumeItemResumeRes(value, report, fmt.Sprintf("%s[%d]{id=238}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABFailedToSetupItemHOReqAck(v *s18.ERABFailedToSetupItemHOReqAck, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationCause(&v.Cause, report, path+".cause", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABFailedToSetupItemHOReqAckExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABFailedtoSetupListHOReqAck(v *s19.ERABFailedtoSetupListHOReqAck, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s18.ERABFailedtoSetupItemHOReqAckIEs().ERABFailedtoSetupItemHOReqAck().Info()}
		s30.BridgeMergeNestedValidation(report, s33.BridgeERABFailedtoSetupItemHOReqAckIEValueValidateS1APIEContainer(s18.ERABFailedtoSetupItemHOReqAckIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s18.ERABFailedtoSetupItemHOReqAckIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(21):
				if value, ok := fields[i].Value.AsERABFailedtoSetupItemHOReqAck(); ok {
					BridgeWalkValidationERABFailedToSetupItemHOReqAck(value, report, fmt.Sprintf("%s[%d]{id=21}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABItem(v *s19.ERABItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationCause(&v.Cause, report, path+".cause", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABLevelQoSParameters(v *s21.ERABLevelQoSParameters, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationAllocationAndRetentionPriority(&v.AllocationRetentionPriority, report, path+".allocationRetentionPriority", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.GbrQosInformation != nil {
		BridgeWalkValidationGBRQosInformation(v.GbrQosInformation, report, path+".gbrQosInformation", false)
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s10.ERABQoSParametersExtIEs().DownlinkPacketLossRate().Info()), s00.FieldInfo(s10.ERABQoSParametersExtIEs().UplinkPacketLossRate().Info())}
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABQoSParametersExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABList(v *s19.ERABList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s19.ERABItemIEs().ERABItem().Info()}
		s30.BridgeMergeNestedValidation(report, s33.BridgeERABItemIEValueValidateS1APIEContainer(s19.ERABItemIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s19.ERABItemIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(35):
				if value, ok := fields[i].Value.AsERABItem(); ok {
					BridgeWalkValidationERABItem(value, report, fmt.Sprintf("%s[%d]{id=35}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABModificationConfirm(v *s49.ERABModificationConfirm, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s49.ERABModificationConfirmIEs().MMEUES1APID().Info(), s49.ERABModificationConfirmIEs().ENBUES1APID().Info(), s49.ERABModificationConfirmIEs().ERABModifyListBearerModConf().Info(), s49.ERABModificationConfirmIEs().ERABFailedToModifyListBearerModConf().Info(), s49.ERABModificationConfirmIEs().ERABToBeReleasedListBearerModConf().Info(), s49.ERABModificationConfirmIEs().CriticalityDiagnostics().Info(), s49.ERABModificationConfirmIEs().CSGMembershipStatus().Info()}
			s30.BridgeMergeNestedValidation(report, s49.BridgeERABModificationConfirmIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(203):
				if value, ok := fields[i].Value.AsERABModifyListBearerModConf(); ok {
					BridgeWalkValidationERABModifyListBearerModConf(value, report, fmt.Sprintf("%s[%d]{id=203}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(205):
				if value, ok := fields[i].Value.AsERABFailedToModifyListBearerModConf(); ok {
					BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=205}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(210):
				if value, ok := fields[i].Value.AsERABToBeReleasedListBearerModConf(); ok {
					BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=210}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationERABModifyItemBearerModConf(v *s19.ERABModifyItemBearerModConf, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABModifyItemBearerModConfExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABModifyItemBearerModRes(v *s19.ERABModifyItemBearerModRes, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABModifyItemBearerModResExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABModifyListBearerModConf(v *s19.ERABModifyListBearerModConf, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s19.ERABModifyItemBearerModConfIEs().ERABModifyItemBearerModConf().Info()}
		s30.BridgeMergeNestedValidation(report, s33.BridgeERABModifyItemBearerModConfIEValueValidateS1APIEContainer(s19.ERABModifyItemBearerModConfIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s19.ERABModifyItemBearerModConfIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(204):
				if value, ok := fields[i].Value.AsERABModifyItemBearerModConf(); ok {
					BridgeWalkValidationERABModifyItemBearerModConf(value, report, fmt.Sprintf("%s[%d]{id=204}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABModifyListBearerModRes(v *s19.ERABModifyListBearerModRes, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s19.ERABModifyItemBearerModResIEs().ERABModifyItemBearerModRes().Info()}
		s30.BridgeMergeNestedValidation(report, s33.BridgeERABModifyItemBearerModResIEValueValidateS1APIEContainer(s19.ERABModifyItemBearerModResIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s19.ERABModifyItemBearerModResIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(37):
				if value, ok := fields[i].Value.AsERABModifyItemBearerModRes(); ok {
					BridgeWalkValidationERABModifyItemBearerModRes(value, report, fmt.Sprintf("%s[%d]{id=37}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABNotToBeModifiedItemBearerModInd(v *s19.ERABNotToBeModifiedItemBearerModInd, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABNotToBeModifiedItemBearerModIndExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABNotToBeModifiedListBearerModInd(v *s19.ERABNotToBeModifiedListBearerModInd, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s19.ERABNotToBeModifiedItemBearerModIndIEs().ERABNotToBeModifiedItemBearerModInd().Info()}
		s30.BridgeMergeNestedValidation(report, s33.BridgeERABNotToBeModifiedItemBearerModIndIEValueValidateS1APIEContainer(s19.ERABNotToBeModifiedItemBearerModIndIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s19.ERABNotToBeModifiedItemBearerModIndIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(202):
				if value, ok := fields[i].Value.AsERABNotToBeModifiedItemBearerModInd(); ok {
					BridgeWalkValidationERABNotToBeModifiedItemBearerModInd(value, report, fmt.Sprintf("%s[%d]{id=202}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABReleaseItemBearerRelComp(v *s19.ERABReleaseItemBearerRelComp, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABReleaseItemBearerRelCompExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABReleaseListBearerRelComp(v *s19.ERABReleaseListBearerRelComp, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s19.ERABReleaseItemBearerRelCompIEs().ERABReleaseItemBearerRelComp().Info()}
		s30.BridgeMergeNestedValidation(report, s33.BridgeERABReleaseItemBearerRelCompIEValueValidateS1APIEContainer(s19.ERABReleaseItemBearerRelCompIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s19.ERABReleaseItemBearerRelCompIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(15):
				if value, ok := fields[i].Value.AsERABReleaseItemBearerRelComp(); ok {
					BridgeWalkValidationERABReleaseItemBearerRelComp(value, report, fmt.Sprintf("%s[%d]{id=15}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABSetupItemBearerSURes(v *s19.ERABSetupItemBearerSURes, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABSetupItemBearerSUResExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABSetupItemCtxtSURes(v *s19.ERABSetupItemCtxtSURes, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABSetupItemCtxtSUResExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABSetupListBearerSURes(v *s20.ERABSetupListBearerSURes, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s19.ERABSetupItemBearerSUResIEs().ERABSetupItemBearerSURes().Info()}
		s30.BridgeMergeNestedValidation(report, s33.BridgeERABSetupItemBearerSUResIEValueValidateS1APIEContainer(s19.ERABSetupItemBearerSUResIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s19.ERABSetupItemBearerSUResIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(39):
				if value, ok := fields[i].Value.AsERABSetupItemBearerSURes(); ok {
					BridgeWalkValidationERABSetupItemBearerSURes(value, report, fmt.Sprintf("%s[%d]{id=39}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABSetupListCtxtSURes(v *s20.ERABSetupListCtxtSURes, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s20.ERABSetupItemCtxtSUResIEs().ERABSetupItemCtxtSURes().Info()}
		s30.BridgeMergeNestedValidation(report, s33.BridgeERABSetupItemCtxtSUResIEValueValidateS1APIEContainer(s19.ERABSetupItemCtxtSUResIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s19.ERABSetupItemCtxtSUResIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(50):
				if value, ok := fields[i].Value.AsERABSetupItemCtxtSURes(); ok {
					BridgeWalkValidationERABSetupItemCtxtSURes(value, report, fmt.Sprintf("%s[%d]{id=50}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABSubjecttoDataForwardingList(v *s20.ERABSubjecttoDataForwardingList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s18.ERABDataForwardingItemIEs().ERABDataForwardingItem().Info()}
		s30.BridgeMergeNestedValidation(report, s33.BridgeERABDataForwardingItemIEValueValidateS1APIEContainer(s18.ERABDataForwardingItemIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s18.ERABDataForwardingItemIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(14):
				if value, ok := fields[i].Value.AsERABDataForwardingItem(); ok {
					BridgeWalkValidationERABDataForwardingItem(value, report, fmt.Sprintf("%s[%d]{id=14}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeModifiedItemBearerModInd(v *s20.ERABToBeModifiedItemBearerModInd, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABToBeModifiedItemBearerModIndExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABToBeModifiedListBearerModInd(v *s20.ERABToBeModifiedListBearerModInd, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s20.ERABToBeModifiedItemBearerModIndIEs().ERABToBeModifiedItemBearerModInd().Info()}
		s30.BridgeMergeNestedValidation(report, s33.BridgeERABToBeModifiedItemBearerModIndIEValueValidateS1APIEContainer(s20.ERABToBeModifiedItemBearerModIndIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s20.ERABToBeModifiedItemBearerModIndIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(200):
				if value, ok := fields[i].Value.AsERABToBeModifiedItemBearerModInd(); ok {
					BridgeWalkValidationERABToBeModifiedItemBearerModInd(value, report, fmt.Sprintf("%s[%d]{id=200}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABToBeSwitchedULItem(v *s20.ERABToBeSwitchedULItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABToBeSwitchedULItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABToBeSwitchedULList(v *s20.ERABToBeSwitchedULList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s20.ERABToBeSwitchedULItemIEs().ERABToBeSwitchedULItem().Info()}
		s30.BridgeMergeNestedValidation(report, s33.BridgeERABToBeSwitchedULItemIEValueValidateS1APIEContainer(s20.ERABToBeSwitchedULItemIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s20.ERABToBeSwitchedULItemIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(94):
				if value, ok := fields[i].Value.AsERABToBeSwitchedULItem(); ok {
					BridgeWalkValidationERABToBeSwitchedULItem(value, report, fmt.Sprintf("%s[%d]{id=94}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationERABUsageReportItem(v *s20.ERABUsageReportItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s33.BridgeERABUsageReportItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationERABUsageReportList(v *s20.ERABUsageReportList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		rows := []s00.FieldInfo{s20.ERABUsageReportItemIEs().ERABUsageReportItem().Info()}
		s30.BridgeMergeNestedValidation(report, s33.BridgeERABUsageReportItemIEValueValidateS1APIEContainer(s20.ERABUsageReportItemIEContainer{field}, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		fields := s20.ERABUsageReportItemIEContainer{field}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(267):
				if value, ok := fields[i].Value.AsERABUsageReportItem(); ok {
					BridgeWalkValidationERABUsageReportItem(value, report, fmt.Sprintf("%s[%d]{id=267}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationEUTRANCGI(v *s20.EUTRANCGI, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s33.BridgeEUTRANCGIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationEUTRANResponse(v *s21.EUTRANResponse, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationEUTRANcellLoadReportingResponse(&v.EUTRANcellLoadReportingResponse, report, path+".eUTRANcellLoadReportingResponse", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEUTRANcellLoadReportingResponse(v *s21.EUTRANcellLoadReportingResponse, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationEmergencyAreaIDBroadcast(v *s26.EmergencyAreaIDBroadcast, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationEmergencyAreaIDBroadcastItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationEmergencyAreaIDBroadcastItem(v *s26.EmergencyAreaIDBroadcastItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationCompletedCellinEAI(&v.CompletedCellinEAI, report, path+".completedCellinEAI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s33.BridgeEmergencyAreaIDBroadcastItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationEmergencyAreaIDCancelled(v *s25.EmergencyAreaIDCancelled, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationEmergencyAreaIDCancelledItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationEmergencyAreaIDCancelledItem(v *s25.EmergencyAreaIDCancelledItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationCancelledCellinEAI(&v.CancelledCellinEAI, report, path+".cancelledCellinEAI", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s34.BridgeEmergencyAreaIDCancelledItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationEmergencyAreaIDList(v *s00.EmergencyAreaIDList, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationEmergencyAreaIDListForRestart(v *s00.EmergencyAreaIDListForRestart, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationEventTriggeredCellLoadReportingRequest(v *s21.EventTriggeredCellLoadReportingRequest, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationEventTriggeredCellLoadReportingResponse(v *s21.EventTriggeredCellLoadReportingResponse, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationCellLoadReportingResponse(&v.CellLoadReportingResponse, report, path+".cellLoadReportingResponse", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationExpectedUEActivityBehaviour(v *s21.ExpectedUEActivityBehaviour, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s34.BridgeExpectedUEActivityBehaviourExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationExpectedUEBehaviour(v *s21.ExpectedUEBehaviour, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.ExpectedActivity != nil {
		BridgeWalkValidationExpectedUEActivityBehaviour(v.ExpectedActivity, report, path+".expectedActivity", false)
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
				s30.BridgeMergeNestedValidation(report, s34.BridgeExpectedUEBehaviourExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationFiveGSTAI(v *s21.FiveGSTAI, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s34.BridgeFiveGSTAIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationForbiddenLACs(v *s00.ForbiddenLACs, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationForbiddenLAs(v *s21.ForbiddenLAs, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationForbiddenLAsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationForbiddenLAsItem(v *s21.ForbiddenLAsItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationForbiddenLACs(&v.ForbiddenLACs, report, path+".forbiddenLACs", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s34.BridgeForbiddenLAsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationForbiddenTACs(v *s00.ForbiddenTACs, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationForbiddenTAs(v *s21.ForbiddenTAs, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationForbiddenTAsItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationForbiddenTAsItem(v *s21.ForbiddenTAsItem, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationForbiddenTACs(&v.ForbiddenTACs, report, path+".forbiddenTACs", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s34.BridgeForbiddenTAsItemExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationGBRQosInformation(v *s21.GBRQosInformation, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s11.GBRQosInformationExtIEs().ExtendedERABMaximumBitrateDL().Info()), s00.FieldInfo(s11.GBRQosInformationExtIEs().ExtendedERABMaximumBitrateUL().Info()), s00.FieldInfo(s11.GBRQosInformationExtIEs().ExtendedERABGuaranteedBitrateDL().Info()), s00.FieldInfo(s11.GBRQosInformationExtIEs().ExtendedERABGuaranteedBitrateUL().Info())}
				s30.BridgeMergeNestedValidation(report, s34.BridgeGBRQosInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationGNB(v *s21.GNB, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationGlobalGNBID(&v.GlobalGNBID, report, path+".global-gNB-ID", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s34.BridgeGNBExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationGNBIdentity(v *s21.GNBIdentity, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationGUMMEI(v *s21.GUMMEI, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s34.BridgeGUMMEIExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationGUMMEIList(v *s21.GUMMEIList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationGUMMEI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationGlobalENBID(v *s21.GlobalENBID, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationENBID(&v.ENBID, report, path+".eNB-ID", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s34.BridgeGlobalENBIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationGlobalEnGNBID(v *s21.GlobalEnGNBID, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s34.BridgeGlobalEnGNBIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationGlobalGNBID(v *s21.GlobalGNBID, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationGNBIdentity(&v.GNBID, report, path+".gNB-ID", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s30.BridgeMergeNestedValidation(report, s34.BridgeGlobalGNBIDExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationHOReport(v *s25.HOReport, report *s25.ValidationReport, path string, skipRoot bool) {
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
	BridgeWalkValidationIRATCellID(&v.HosourceID, report, path+".hosourceID", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationIRATCellID(&v.HoTargetID, report, path+".hoTargetID", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationCandidateCellList(&v.CandidateCellList, report, path+".candidateCellList", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.CandidatePCIList != nil {
		BridgeWalkValidationCandidatePCIList(&v.CandidatePCIList, report, path+".candidatePCIList", false)
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverCancel(v *s29.HandoverCancel, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s21.HandoverCancelIEs().MMEUES1APID().Info(), s21.HandoverCancelIEs().ENBUES1APID().Info(), s21.HandoverCancelIEs().Cause().Info()}
			s30.BridgeMergeNestedValidation(report, s34.BridgeHandoverCancelIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverCancelAcknowledge(v *s29.HandoverCancelAcknowledge, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s26.HandoverCancelAcknowledgeIEs().MMEUES1APID().Info(), s26.HandoverCancelAcknowledgeIEs().ENBUES1APID().Info(), s26.HandoverCancelAcknowledgeIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s34.BridgeHandoverCancelAcknowledgeIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverCommand(v *s50.HandoverCommand, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s50.HandoverCommandIEs().MMEUES1APID().Info(), s50.HandoverCommandIEs().ENBUES1APID().Info(), s50.HandoverCommandIEs().HandoverType().Info(), s50.HandoverCommandIEs().NASSecurityParametersfromEUTRAN().Info(), s50.HandoverCommandIEs().ERABSubjecttoDataForwardingList().Info(), s50.HandoverCommandIEs().ERABtoReleaseListHOCmd().Info(), s50.HandoverCommandIEs().TargetToSourceTransparentContainer().Info(), s50.HandoverCommandIEs().TargetToSourceTransparentContainerSecondary().Info(), s50.HandoverCommandIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s50.BridgeHandoverCommandIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(12):
				if value, ok := fields[i].Value.AsERABSubjecttoDataForwardingList(); ok {
					BridgeWalkValidationERABSubjecttoDataForwardingList(value, report, fmt.Sprintf("%s[%d]{id=12}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(13):
				if value, ok := fields[i].Value.AsERABtoReleaseListHOCmd(); ok {
					BridgeWalkValidationERABList(value, report, fmt.Sprintf("%s[%d]{id=13}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverFailure(v *s29.HandoverFailure, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s26.HandoverFailureIEs().MMEUES1APID().Info(), s26.HandoverFailureIEs().Cause().Info(), s26.HandoverFailureIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s34.BridgeHandoverFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverPreparationFailure(v *s29.HandoverPreparationFailure, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s26.HandoverPreparationFailureIEs().MMEUES1APID().Info(), s26.HandoverPreparationFailureIEs().ENBUES1APID().Info(), s26.HandoverPreparationFailureIEs().Cause().Info(), s26.HandoverPreparationFailureIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, s34.BridgeHandoverPreparationFailureIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(2):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=2}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverRequestAcknowledge(v *s49.HandoverRequestAcknowledge, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s49.HandoverRequestAcknowledgeIEs().MMEUES1APID().Info(), s49.HandoverRequestAcknowledgeIEs().ENBUES1APID().Info(), s49.HandoverRequestAcknowledgeIEs().ERABAdmittedList().Info(), s49.HandoverRequestAcknowledgeIEs().ERABFailedToSetupListHOReqAck().Info(), s49.HandoverRequestAcknowledgeIEs().TargetToSourceTransparentContainer().Info(), s49.HandoverRequestAcknowledgeIEs().CSGId().Info(), s49.HandoverRequestAcknowledgeIEs().CriticalityDiagnostics().Info(), s49.HandoverRequestAcknowledgeIEs().CellAccessMode().Info(), s49.HandoverRequestAcknowledgeIEs().CEModeBSupportIndicator().Info()}
			s30.BridgeMergeNestedValidation(report, s49.BridgeHandoverRequestAcknowledgeIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(18):
				if value, ok := fields[i].Value.AsERABAdmittedList(); ok {
					BridgeWalkValidationERABAdmittedList(value, report, fmt.Sprintf("%s[%d]{id=18}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(19):
				if value, ok := fields[i].Value.AsERABFailedToSetupListHOReqAck(); ok {
					BridgeWalkValidationERABFailedtoSetupListHOReqAck(value, report, fmt.Sprintf("%s[%d]{id=19}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(58):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=58}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationHandoverSuccess(v *s21.HandoverSuccess, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s11.HandoverSuccessIEs().MMEUES1APID().Info(), s11.HandoverSuccessIEs().ENBUES1APID().Info()}
			s30.BridgeMergeNestedValidation(report, s34.BridgeHandoverSuccessIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationIEsECGIList(v *s21.IEsECGIList, report *s25.ValidationReport, path string, skipRoot bool) {
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
		BridgeWalkValidationEUTRANCGI(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationIRATCellID(v *s21.IRATCellID, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgePagingFieldPerPadding(v *Paging) *aper.FinalPadding             { return &v.perPadding }
func BridgePagingFieldReceived(v *Paging) *bool                            { return &v.received }
func BridgePagingFieldReceivedAbsolute(v *Paging) *bool                    { return &v.receivedAbsolute }
func BridgePagingFieldReceivedBytes(v *Paging) *aper.WireSpan              { return &v.receivedBytes }
func BridgePagingFieldReceivedLocation(v *Paging) *aper.Location           { return &v.receivedLocation }
func BridgePagingIEValueFieldId(v *PagingIEValue) *s00.ProtocolIEID        { return &v.id }
func BridgePagingIEValueFieldIsOpaque(v *PagingIEValue) *bool              { return &v.isOpaque }
func BridgePagingIEValueFieldOpaque(v *PagingIEValue) *aper.OpaqueOpenType { return &v.opaque }
func BridgePagingIEValueFieldRowAssistanceDataForPaging(v *PagingIEValue) **s31.AssistanceDataForPaging {
	return &v.rowAssistanceDataForPaging
}
func BridgePagingIEValueFieldRowCEModeBRestricted(v *PagingIEValue) **s00.CEModeBRestricted {
	return &v.rowCEModeBRestricted
}
func BridgePagingIEValueFieldRowCNDomain(v *PagingIEValue) **s00.CNDomain   { return &v.rowCNDomain }
func BridgePagingIEValueFieldRowCSGIdList(v *PagingIEValue) **s17.CSGIdList { return &v.rowCSGIdList }
func BridgePagingIEValueFieldRowDataSize(v *PagingIEValue) **s00.DataSize   { return &v.rowDataSize }
func BridgePagingIEValueFieldRowEnhancedCoverageRestricted(v *PagingIEValue) **s00.EnhancedCoverageRestricted {
	return &v.rowEnhancedCoverageRestricted
}
func BridgePagingIEValueFieldRowExtendedUEIdentityIndexValue(v *PagingIEValue) **s00.ExtendedUEIdentityIndexValue {
	return &v.rowExtendedUEIdentityIndexValue
}
func BridgePagingIEValueFieldRowNBIoTPagingDRX(v *PagingIEValue) **s00.NBIoTPagingDRX {
	return &v.rowNBIoTPagingDRX
}
func BridgePagingIEValueFieldRowNBIoTPagingEDRXInformation(v *PagingIEValue) **s23.NBIoTPagingEDRXInformation {
	return &v.rowNBIoTPagingEDRXInformation
}
func BridgePagingIEValueFieldRowNBIoTUEIdentityIndexValue(v *PagingIEValue) **s00.NBIoTUEIdentityIndexValue {
	return &v.rowNBIoTUEIdentityIndexValue
}
func BridgePagingIEValueFieldRowPagingCause(v *PagingIEValue) **s00.PagingCause {
	return &v.rowPagingCause
}
func BridgePagingIEValueFieldRowPagingDRX(v *PagingIEValue) **s00.PagingDRX { return &v.rowPagingDRX }
func BridgePagingIEValueFieldRowPagingEDRXInformation(v *PagingIEValue) **s23.PagingEDRXInformation {
	return &v.rowPagingEDRXInformation
}
func BridgePagingIEValueFieldRowPagingPriority(v *PagingIEValue) **s00.PagingPriority {
	return &v.rowPagingPriority
}
func BridgePagingIEValueFieldRowTAIList(v *PagingIEValue) **s42.TAIList { return &v.rowTAIList }
func BridgePagingIEValueFieldRowUEIdentityIndexValue(v *PagingIEValue) **s00.UEIdentityIndexValue {
	return &v.rowUEIdentityIndexValue
}
func BridgePagingIEValueFieldRowUEPagingID(v *PagingIEValue) **s36.UEPagingID {
	return &v.rowUEPagingID
}
func BridgePagingIEValueFieldRowUERadioCapabilityForPaging(v *PagingIEValue) **s00.UERadioCapabilityForPaging {
	return &v.rowUERadioCapabilityForPaging
}
func BridgePagingIEValueFieldRowWUSAssistanceInformation(v *PagingIEValue) **WUSAssistanceInformation {
	return &v.rowWUSAssistanceInformation
}
func BridgePagingMethodMarshalAPERBudget(v *Paging, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePagingMethodUnmarshalAPERFrom(v *Paging, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePagingMethodUnmarshalAPERWithOptions(v *Paging, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePagingValueCodecFieldCapture(v *PagingValueCodec) *func(Paging, aper.DecodeState) (Paging, aper.Snapshot) {
	return &v.capture
}
func BridgePagingValueCodecFieldCompare(v *PagingValueCodec) *func(Paging, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingValueCodecFieldContext(v *PagingValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingValueCodecFieldDecode(v *PagingValueCodec) *func([]byte, aper.DecodeState) (Paging, error) {
	return &v.decode
}
func BridgePagingValueCodecFieldEncode(v *PagingValueCodec) *func(Paging, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingValueCodecFieldPath(v *PagingValueCodec) *aper.Path     { return &v.path }
func BridgeTraceStartFieldPerPadding(v *TraceStart) *aper.FinalPadding   { return &v.perPadding }
func BridgeTraceStartFieldReceived(v *TraceStart) *bool                  { return &v.received }
func BridgeTraceStartFieldReceivedAbsolute(v *TraceStart) *bool          { return &v.receivedAbsolute }
func BridgeTraceStartFieldReceivedBytes(v *TraceStart) *aper.WireSpan    { return &v.receivedBytes }
func BridgeTraceStartFieldReceivedLocation(v *TraceStart) *aper.Location { return &v.receivedLocation }
func BridgeTraceStartMethodMarshalAPERBudget(v *TraceStart, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTraceStartMethodUnmarshalAPERFrom(v *TraceStart, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTraceStartMethodUnmarshalAPERWithOptions(v *TraceStart, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTraceStartValueCodecFieldCapture(v *TraceStartValueCodec) *func(TraceStart, aper.DecodeState) (TraceStart, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceStartValueCodecFieldCompare(v *TraceStartValueCodec) *func(TraceStart, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceStartValueCodecFieldContext(v *TraceStartValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceStartValueCodecFieldDecode(v *TraceStartValueCodec) *func([]byte, aper.DecodeState) (TraceStart, error) {
	return &v.decode
}
func BridgeTraceStartValueCodecFieldEncode(v *TraceStartValueCodec) *func(TraceStart, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceStartValueCodecFieldPath(v *TraceStartValueCodec) *aper.Path { return &v.path }

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *PagingIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 80:
		if value, ok := v.AsUEIdentityIndexValue(); ok {
			return value, true
		}
	case 43:
		if value, ok := v.AsUEPagingID(); ok {
			return value, true
		}
	case 44:
		if value, ok := v.AsPagingDRX(); ok {
			return value, true
		}
	case 109:
		if value, ok := v.AsCNDomain(); ok {
			return value, true
		}
	case 46:
		if value, ok := v.AsTAIList(); ok {
			return value, true
		}
	case 128:
		if value, ok := v.AsCSGIdList(); ok {
			return value, true
		}
	case 151:
		if value, ok := v.AsPagingPriority(); ok {
			return value, true
		}
	case 198:
		if value, ok := v.AsUERadioCapabilityForPaging(); ok {
			return value, true
		}
	case 211:
		if value, ok := v.AsAssistanceDataForPaging(); ok {
			return value, true
		}
	case 227:
		if value, ok := v.AsPagingEDRXInformation(); ok {
			return value, true
		}
	case 231:
		if value, ok := v.AsExtendedUEIdentityIndexValue(); ok {
			return value, true
		}
	case 239:
		if value, ok := v.AsNBIoTPagingEDRXInformation(); ok {
			return value, true
		}
	case 244:
		if value, ok := v.AsNBIoTUEIdentityIndexValue(); ok {
			return value, true
		}
	case 251:
		if value, ok := v.AsEnhancedCoverageRestricted(); ok {
			return value, true
		}
	case 271:
		if value, ok := v.AsCEModeBRestricted(); ok {
			return value, true
		}
	case 304:
		if value, ok := v.AsDataSize(); ok {
			return value, true
		}
	case 323:
		if value, ok := v.AsWUSAssistanceInformation(); ok {
			return value, true
		}
	case 324:
		if value, ok := v.AsNBIoTPagingDRX(); ok {
			return value, true
		}
	case 331:
		if value, ok := v.AsPagingCause(); ok {
			return value, true
		}
	}
	return nil, false
}
