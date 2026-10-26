// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s64 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s64

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s09 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s09"
	s15 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s40 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s40"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s44 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s44"
	s45 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s45"
	s46 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s46"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	s49 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s49"
	s50 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s50"
	s52 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s52"
	s54 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s54"
	s55 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s55"
	s57 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s57"
	s58 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s58"
	s59 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s59"
	s60 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s60"
	s61 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s61"
	s62 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s62"
	s63 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s63"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

func NewHandoverRequest(fields s59.HandoverRequestIEContainer, options ...aper.BuildOption) (s60.HandoverRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s60.HandoverRequest{}, aper.OperationError(err, "HandoverRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s59.HandoverRequestIEField](bb, uint64(len(fields))); err != nil {
		return s60.HandoverRequest{}, aper.OperationError(err, "HandoverRequest")
	}
	v := s60.HandoverRequest{ProtocolIEs: make(s59.HandoverRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateHandoverRequestBudget(&v, budget)
	if err != nil {
		return s60.HandoverRequest{}, aper.OperationError(err, "HandoverRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s60.HandoverRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "HandoverRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s60.HandoverRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "HandoverRequest")
	}
	if _, err := s60.BridgeHandoverRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s60.HandoverRequest{}, aper.OperationError(fmt.Errorf("%s %w", "HandoverRequest.protocolIEs:", err), "HandoverRequest")
	}
	return v, aper.OperationError(nil, "HandoverRequest")
}
func NewInitialContextSetupRequest(fields s60.InitialContextSetupRequestIEContainer, options ...aper.BuildOption) (s60.InitialContextSetupRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s60.InitialContextSetupRequest{}, aper.OperationError(err, "InitialContextSetupRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s60.InitialContextSetupRequestIEField](bb, uint64(len(fields))); err != nil {
		return s60.InitialContextSetupRequest{}, aper.OperationError(err, "InitialContextSetupRequest")
	}
	v := s60.InitialContextSetupRequest{ProtocolIEs: make(s60.InitialContextSetupRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateInitialContextSetupRequestBudget(&v, budget)
	if err != nil {
		return s60.InitialContextSetupRequest{}, aper.OperationError(err, "InitialContextSetupRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s60.InitialContextSetupRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "InitialContextSetupRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s60.InitialContextSetupRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "InitialContextSetupRequest")
	}
	if _, err := s60.BridgeInitialContextSetupRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s60.InitialContextSetupRequest{}, aper.OperationError(fmt.Errorf("%s %w", "InitialContextSetupRequest.protocolIEs:", err), "InitialContextSetupRequest")
	}
	return v, aper.OperationError(nil, "InitialContextSetupRequest")
}
func NewPaging(fields s61.PagingIEContainer, options ...aper.BuildOption) (s61.Paging, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s61.Paging{}, aper.OperationError(err, "Paging")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s61.PagingIEField](bb, uint64(len(fields))); err != nil {
		return s61.Paging{}, aper.OperationError(err, "Paging")
	}
	v := s61.Paging{ProtocolIEs: make(s61.PagingIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidatePagingBudget(&v, budget)
	if err != nil {
		return s61.Paging{}, aper.OperationError(err, "Paging")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s61.Paging{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Paging")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s61.Paging{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Paging")
	}
	if _, err := s61.BridgePagingMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s61.Paging{}, aper.OperationError(fmt.Errorf("%s %w", "Paging.protocolIEs:", err), "Paging")
	}
	return v, aper.OperationError(nil, "Paging")
}
func NewUEContextModificationRequest(fields s58.UEContextModificationRequestIEContainer, options ...aper.BuildOption) (s58.UEContextModificationRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s58.UEContextModificationRequest{}, aper.OperationError(err, "UEContextModificationRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s58.UEContextModificationRequestIEField](bb, uint64(len(fields))); err != nil {
		return s58.UEContextModificationRequest{}, aper.OperationError(err, "UEContextModificationRequest")
	}
	v := s58.UEContextModificationRequest{ProtocolIEs: make(s58.UEContextModificationRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateUEContextModificationRequestBudget(&v, budget)
	if err != nil {
		return s58.UEContextModificationRequest{}, aper.OperationError(err, "UEContextModificationRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s58.UEContextModificationRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "UEContextModificationRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s58.UEContextModificationRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "UEContextModificationRequest")
	}
	if _, err := s58.BridgeUEContextModificationRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s58.UEContextModificationRequest{}, aper.OperationError(fmt.Errorf("%s %w", "UEContextModificationRequest.protocolIEs:", err), "UEContextModificationRequest")
	}
	return v, aper.OperationError(nil, "UEContextModificationRequest")
}
func NewTraceStart(fields s60.TraceStartIEContainer, options ...aper.BuildOption) (s61.TraceStart, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s61.TraceStart{}, aper.OperationError(err, "TraceStart")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s60.TraceStartIEField](bb, uint64(len(fields))); err != nil {
		return s61.TraceStart{}, aper.OperationError(err, "TraceStart")
	}
	v := s61.TraceStart{ProtocolIEs: make(s60.TraceStartIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateTraceStartBudget(&v, budget)
	if err != nil {
		return s61.TraceStart{}, aper.OperationError(err, "TraceStart")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s61.TraceStart{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "TraceStart")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s61.TraceStart{}, aper.OperationError(&s25.BuildError{Issues: issues}, "TraceStart")
	}
	if _, err := s61.BridgeTraceStartMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s61.TraceStart{}, aper.OperationError(fmt.Errorf("%s %w", "TraceStart.protocolIEs:", err), "TraceStart")
	}
	return v, aper.OperationError(nil, "TraceStart")
}
func NewWriteReplaceWarningRequest(fields s42.WriteReplaceWarningRequestIEContainer, options ...aper.BuildOption) (WriteReplaceWarningRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return WriteReplaceWarningRequest{}, aper.OperationError(err, "WriteReplaceWarningRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s42.WriteReplaceWarningRequestIEField](bb, uint64(len(fields))); err != nil {
		return WriteReplaceWarningRequest{}, aper.OperationError(err, "WriteReplaceWarningRequest")
	}
	v := WriteReplaceWarningRequest{ProtocolIEs: make(s42.WriteReplaceWarningRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateWriteReplaceWarningRequestBudget(&v, budget)
	if err != nil {
		return WriteReplaceWarningRequest{}, aper.OperationError(err, "WriteReplaceWarningRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return WriteReplaceWarningRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "WriteReplaceWarningRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return WriteReplaceWarningRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "WriteReplaceWarningRequest")
	}
	if _, err := v.marshalAPERBudget(budget, false); err != nil {
		return WriteReplaceWarningRequest{}, aper.OperationError(fmt.Errorf("%s %w", "WriteReplaceWarningRequest.protocolIEs:", err), "WriteReplaceWarningRequest")
	}
	return v, aper.OperationError(nil, "WriteReplaceWarningRequest")
}
func NewWriteReplaceWarningResponse(fields s41.WriteReplaceWarningResponseIEContainer, options ...aper.BuildOption) (WriteReplaceWarningResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return WriteReplaceWarningResponse{}, aper.OperationError(err, "WriteReplaceWarningResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s41.WriteReplaceWarningResponseIEField](bb, uint64(len(fields))); err != nil {
		return WriteReplaceWarningResponse{}, aper.OperationError(err, "WriteReplaceWarningResponse")
	}
	v := WriteReplaceWarningResponse{ProtocolIEs: make(s41.WriteReplaceWarningResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateWriteReplaceWarningResponseBudget(&v, budget)
	if err != nil {
		return WriteReplaceWarningResponse{}, aper.OperationError(err, "WriteReplaceWarningResponse")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return WriteReplaceWarningResponse{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "WriteReplaceWarningResponse")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return WriteReplaceWarningResponse{}, aper.OperationError(&s25.BuildError{Issues: issues}, "WriteReplaceWarningResponse")
	}
	if _, err := v.marshalAPERBudget(budget, false); err != nil {
		return WriteReplaceWarningResponse{}, aper.OperationError(fmt.Errorf("%s %w", "WriteReplaceWarningResponse.protocolIEs:", err), "WriteReplaceWarningResponse")
	}
	return v, aper.OperationError(nil, "WriteReplaceWarningResponse")
}
func NewKillRequest(fields s41.KillRequestIEContainer, options ...aper.BuildOption) (s42.KillRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s42.KillRequest{}, aper.OperationError(err, "KillRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s41.KillRequestIEField](bb, uint64(len(fields))); err != nil {
		return s42.KillRequest{}, aper.OperationError(err, "KillRequest")
	}
	v := s42.KillRequest{ProtocolIEs: make(s41.KillRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateKillRequestBudget(&v, budget)
	if err != nil {
		return s42.KillRequest{}, aper.OperationError(err, "KillRequest")
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return s42.KillRequest{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "KillRequest")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s42.KillRequest{}, aper.OperationError(&s25.BuildError{Issues: issues}, "KillRequest")
	}
	if _, err := s42.BridgeKillRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s42.KillRequest{}, aper.OperationError(fmt.Errorf("%s %w", "KillRequest.protocolIEs:", err), "KillRequest")
	}
	return v, aper.OperationError(nil, "KillRequest")
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

// MMEConfigurationTransferIEContainer is ProtocolIE-Container {{MMEConfigurationTransferIEs}} of TS 36.413: a list of MMEConfigurationTransferIEField values.
type MMEConfigurationTransferIEContainer []MMEConfigurationTransferIEField

// MMEConfigurationTransferIEField is ProtocolIE-Field {{MMEConfigurationTransferIEs}} of TS 36.413: an information element field.
type MMEConfigurationTransferIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         MMEConfigurationTransferIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationTransferIEField) WithoutReplay() MMEConfigurationTransferIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *MMEConfigurationTransferIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *MMEConfigurationTransferIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *MMEConfigurationTransferIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MMEConfigurationTransferIEField{}
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
	var zero MMEConfigurationTransferIEValue

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
	capture func(s50.HandoverCommand, aper.DecodeState,

	) (s50.HandoverCommand, aper.Snapshot,

	)
	compare func(s50.HandoverCommand, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s50.HandoverCommand,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s50.HandoverCommand,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s50.HandoverCommand,

		error)
	inject func(s50.HandoverCommand,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b HandoverCommandSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCommandSuccessfulBinding) Codec() s50.HandoverCommandValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s50.HandoverCommandValueCodec{}
	}
	return func() s50.HandoverCommandValueCodec {
		sealed := s50.HandoverCommandValueCodec{}
		*s50.BridgeHandoverCommandValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s50.BridgeHandoverCommandValueCodecFieldDecode(&sealed) = b.decode
		*s50.BridgeHandoverCommandValueCodecFieldEncode(&sealed) = func(value s50.HandoverCommand,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s50.BridgeHandoverCommandValueCodecFieldCapture(&sealed) = b.capture
		*s50.BridgeHandoverCommandValueCodecFieldCompare(&sealed) = b.compare
		*s50.BridgeHandoverCommandValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverCommandSuccessfulBinding) Build(body s50.HandoverCommand,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s49.HandoverRequestAcknowledge, aper.DecodeState,

	) (s49.HandoverRequestAcknowledge, aper.Snapshot,

	)
	compare func(s49.HandoverRequestAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s49.HandoverRequestAcknowledge,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s49.HandoverRequestAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s49.HandoverRequestAcknowledge,

		error)
	inject func(s49.HandoverRequestAcknowledge,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestAcknowledgeSuccessfulBinding) Codec() s49.HandoverRequestAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s49.HandoverRequestAcknowledgeValueCodec{}
	}
	return func() s49.HandoverRequestAcknowledgeValueCodec {
		sealed := s49.HandoverRequestAcknowledgeValueCodec{}
		*s49.BridgeHandoverRequestAcknowledgeValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s49.BridgeHandoverRequestAcknowledgeValueCodecFieldDecode(&sealed) = b.decode
		*s49.BridgeHandoverRequestAcknowledgeValueCodecFieldEncode(&sealed) = func(value s49.HandoverRequestAcknowledge,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s49.BridgeHandoverRequestAcknowledgeValueCodecFieldCapture(&sealed) = b.capture
		*s49.BridgeHandoverRequestAcknowledgeValueCodecFieldCompare(&sealed) = b.compare
		*s49.BridgeHandoverRequestAcknowledgeValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverRequestAcknowledgeSuccessfulBinding) Build(body s49.HandoverRequestAcknowledge,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s58.PathSwitchRequestAcknowledge, aper.DecodeState,

	) (s58.PathSwitchRequestAcknowledge, aper.Snapshot,

	)
	compare func(s58.PathSwitchRequestAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s58.PathSwitchRequestAcknowledge,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s58.PathSwitchRequestAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s58.PathSwitchRequestAcknowledge,

		error)
	inject func(s58.PathSwitchRequestAcknowledge,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestAcknowledgeSuccessfulBinding) Codec() s58.PathSwitchRequestAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s58.PathSwitchRequestAcknowledgeValueCodec{}
	}
	return func() s58.PathSwitchRequestAcknowledgeValueCodec {
		sealed := s58.PathSwitchRequestAcknowledgeValueCodec{}
		*s58.BridgePathSwitchRequestAcknowledgeValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s58.BridgePathSwitchRequestAcknowledgeValueCodecFieldDecode(&sealed) = b.decode
		*s58.BridgePathSwitchRequestAcknowledgeValueCodecFieldEncode(&sealed) = func(value s58.PathSwitchRequestAcknowledge,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s58.BridgePathSwitchRequestAcknowledgeValueCodecFieldCapture(&sealed) = b.capture
		*s58.BridgePathSwitchRequestAcknowledgeValueCodecFieldCompare(&sealed) = b.compare
		*s58.BridgePathSwitchRequestAcknowledgeValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b PathSwitchRequestAcknowledgeSuccessfulBinding) Build(body s58.PathSwitchRequestAcknowledge,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s29.HandoverCancelAcknowledge, aper.DecodeState,

	) (s29.HandoverCancelAcknowledge, aper.Snapshot,

	)
	compare func(s29.HandoverCancelAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s29.HandoverCancelAcknowledge,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s29.HandoverCancelAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s29.HandoverCancelAcknowledge,

		error)
	inject func(s29.HandoverCancelAcknowledge,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b HandoverCancelAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverCancelAcknowledgeSuccessfulBinding) Codec() s29.HandoverCancelAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s29.HandoverCancelAcknowledgeValueCodec{}
	}
	return func() s29.HandoverCancelAcknowledgeValueCodec {
		sealed := s29.HandoverCancelAcknowledgeValueCodec{}
		*s29.BridgeHandoverCancelAcknowledgeValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s29.BridgeHandoverCancelAcknowledgeValueCodecFieldDecode(&sealed) = b.decode
		*s29.BridgeHandoverCancelAcknowledgeValueCodecFieldEncode(&sealed) = func(value s29.HandoverCancelAcknowledge,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s29.BridgeHandoverCancelAcknowledgeValueCodecFieldCapture(&sealed) = b.capture
		*s29.BridgeHandoverCancelAcknowledgeValueCodecFieldCompare(&sealed) = b.compare
		*s29.BridgeHandoverCancelAcknowledgeValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverCancelAcknowledgeSuccessfulBinding) Build(body s29.HandoverCancelAcknowledge,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s57.ERABSetupResponse, aper.DecodeState,

	) (s57.ERABSetupResponse, aper.Snapshot,

	)
	compare func(s57.ERABSetupResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s57.ERABSetupResponse,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s57.ERABSetupResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s57.ERABSetupResponse,

		error)
	inject func(s57.ERABSetupResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ERABSetupResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABSetupResponseSuccessfulBinding) Codec() s57.ERABSetupResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s57.ERABSetupResponseValueCodec{}
	}
	return func() s57.ERABSetupResponseValueCodec {
		sealed := s57.ERABSetupResponseValueCodec{}
		*s57.BridgeERABSetupResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s57.BridgeERABSetupResponseValueCodecFieldDecode(&sealed) = b.decode
		*s57.BridgeERABSetupResponseValueCodecFieldEncode(&sealed) = func(value s57.ERABSetupResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s57.BridgeERABSetupResponseValueCodecFieldCapture(&sealed) = b.capture
		*s57.BridgeERABSetupResponseValueCodecFieldCompare(&sealed) = b.compare
		*s57.BridgeERABSetupResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ERABSetupResponseSuccessfulBinding) Build(body s57.ERABSetupResponse,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s57.ERABModifyResponse, aper.DecodeState,

	) (s57.ERABModifyResponse, aper.Snapshot,

	)
	compare func(s57.ERABModifyResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s57.ERABModifyResponse,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s57.ERABModifyResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s57.ERABModifyResponse,

		error)
	inject func(s57.ERABModifyResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ERABModifyResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModifyResponseSuccessfulBinding) Codec() s57.ERABModifyResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s57.ERABModifyResponseValueCodec{}
	}
	return func() s57.ERABModifyResponseValueCodec {
		sealed := s57.ERABModifyResponseValueCodec{}
		*s57.BridgeERABModifyResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s57.BridgeERABModifyResponseValueCodecFieldDecode(&sealed) = b.decode
		*s57.BridgeERABModifyResponseValueCodecFieldEncode(&sealed) = func(value s57.ERABModifyResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s57.BridgeERABModifyResponseValueCodecFieldCapture(&sealed) = b.capture
		*s57.BridgeERABModifyResponseValueCodecFieldCompare(&sealed) = b.compare
		*s57.BridgeERABModifyResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ERABModifyResponseSuccessfulBinding) Build(body s57.ERABModifyResponse,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s57.ERABReleaseResponse, aper.DecodeState,

	) (s57.ERABReleaseResponse, aper.Snapshot,

	)
	compare func(s57.ERABReleaseResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s57.ERABReleaseResponse,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s57.ERABReleaseResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s57.ERABReleaseResponse,

		error)
	inject func(s57.ERABReleaseResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ERABReleaseResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABReleaseResponseSuccessfulBinding) Codec() s57.ERABReleaseResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s57.ERABReleaseResponseValueCodec{}
	}
	return func() s57.ERABReleaseResponseValueCodec {
		sealed := s57.ERABReleaseResponseValueCodec{}
		*s57.BridgeERABReleaseResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s57.BridgeERABReleaseResponseValueCodecFieldDecode(&sealed) = b.decode
		*s57.BridgeERABReleaseResponseValueCodecFieldEncode(&sealed) = func(value s57.ERABReleaseResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s57.BridgeERABReleaseResponseValueCodecFieldCapture(&sealed) = b.capture
		*s57.BridgeERABReleaseResponseValueCodecFieldCompare(&sealed) = b.compare
		*s57.BridgeERABReleaseResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ERABReleaseResponseSuccessfulBinding) Build(body s57.ERABReleaseResponse,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s50.InitialContextSetupResponse, aper.DecodeState,

	) (s50.InitialContextSetupResponse, aper.Snapshot,

	)
	compare func(s50.InitialContextSetupResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s50.InitialContextSetupResponse,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s50.InitialContextSetupResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s50.InitialContextSetupResponse,

		error)
	inject func(s50.InitialContextSetupResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupResponseSuccessfulBinding) Codec() s50.InitialContextSetupResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s50.InitialContextSetupResponseValueCodec{}
	}
	return func() s50.InitialContextSetupResponseValueCodec {
		sealed := s50.InitialContextSetupResponseValueCodec{}
		*s50.BridgeInitialContextSetupResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s50.BridgeInitialContextSetupResponseValueCodecFieldDecode(&sealed) = b.decode
		*s50.BridgeInitialContextSetupResponseValueCodecFieldEncode(&sealed) = func(value s50.InitialContextSetupResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s50.BridgeInitialContextSetupResponseValueCodecFieldCapture(&sealed) = b.capture
		*s50.BridgeInitialContextSetupResponseValueCodecFieldCompare(&sealed) = b.compare
		*s50.BridgeInitialContextSetupResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b InitialContextSetupResponseSuccessfulBinding) Build(body s50.InitialContextSetupResponse,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s55.ResetAcknowledge, aper.DecodeState,

	) (s55.ResetAcknowledge, aper.Snapshot,

	)
	compare func(s55.ResetAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s55.ResetAcknowledge,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s55.ResetAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s55.ResetAcknowledge,

		error)
	inject func(s55.ResetAcknowledge,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ResetAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ResetAcknowledgeSuccessfulBinding) Codec() s55.ResetAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s55.ResetAcknowledgeValueCodec{}
	}
	return func() s55.ResetAcknowledgeValueCodec {
		sealed := s55.ResetAcknowledgeValueCodec{}
		*s55.BridgeResetAcknowledgeValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s55.BridgeResetAcknowledgeValueCodecFieldDecode(&sealed) = b.decode
		*s55.BridgeResetAcknowledgeValueCodecFieldEncode(&sealed) = func(value s55.ResetAcknowledge,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s55.BridgeResetAcknowledgeValueCodecFieldCapture(&sealed) = b.capture
		*s55.BridgeResetAcknowledgeValueCodecFieldCompare(&sealed) = b.compare
		*s55.BridgeResetAcknowledgeValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ResetAcknowledgeSuccessfulBinding) Build(body s55.ResetAcknowledge,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s54.S1SetupResponse, aper.DecodeState,

	) (s54.S1SetupResponse, aper.Snapshot,

	)
	compare func(s54.S1SetupResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s54.S1SetupResponse,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s54.S1SetupResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s54.S1SetupResponse,

		error)
	inject func(s54.S1SetupResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b S1SetupResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupResponseSuccessfulBinding) Codec() s54.S1SetupResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s54.S1SetupResponseValueCodec{}
	}
	return func() s54.S1SetupResponseValueCodec {
		sealed := s54.S1SetupResponseValueCodec{}
		*s54.BridgeS1SetupResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s54.BridgeS1SetupResponseValueCodecFieldDecode(&sealed) = b.decode
		*s54.BridgeS1SetupResponseValueCodecFieldEncode(&sealed) = func(value s54.S1SetupResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s54.BridgeS1SetupResponseValueCodecFieldCapture(&sealed) = b.capture
		*s54.BridgeS1SetupResponseValueCodecFieldCompare(&sealed) = b.compare
		*s54.BridgeS1SetupResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1SetupResponseSuccessfulBinding) Build(body s54.S1SetupResponse,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s46.UEContextModificationResponse, aper.DecodeState,

	) (s46.UEContextModificationResponse, aper.Snapshot,

	)
	compare func(s46.UEContextModificationResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s46.UEContextModificationResponse,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s46.UEContextModificationResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s46.UEContextModificationResponse,

		error)
	inject func(s46.UEContextModificationResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationResponseSuccessfulBinding) Codec() s46.UEContextModificationResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.UEContextModificationResponseValueCodec{}
	}
	return func() s46.UEContextModificationResponseValueCodec {
		sealed := s46.UEContextModificationResponseValueCodec{}
		*s46.BridgeUEContextModificationResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s46.BridgeUEContextModificationResponseValueCodecFieldDecode(&sealed) = b.decode
		*s46.BridgeUEContextModificationResponseValueCodecFieldEncode(&sealed) = func(value s46.UEContextModificationResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s46.BridgeUEContextModificationResponseValueCodecFieldCapture(&sealed) = b.capture
		*s46.BridgeUEContextModificationResponseValueCodecFieldCompare(&sealed) = b.compare
		*s46.BridgeUEContextModificationResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextModificationResponseSuccessfulBinding) Build(body s46.UEContextModificationResponse,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s57.UEContextReleaseComplete, aper.DecodeState,

	) (s57.UEContextReleaseComplete, aper.Snapshot,

	)
	compare func(s57.UEContextReleaseComplete, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s57.UEContextReleaseComplete,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s57.UEContextReleaseComplete,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s57.UEContextReleaseComplete,

		error)
	inject func(s57.UEContextReleaseComplete,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCompleteSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCompleteSuccessfulBinding) Codec() s57.UEContextReleaseCompleteValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s57.UEContextReleaseCompleteValueCodec{}
	}
	return func() s57.UEContextReleaseCompleteValueCodec {
		sealed := s57.UEContextReleaseCompleteValueCodec{}
		*s57.BridgeUEContextReleaseCompleteValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s57.BridgeUEContextReleaseCompleteValueCodecFieldDecode(&sealed) = b.decode
		*s57.BridgeUEContextReleaseCompleteValueCodecFieldEncode(&sealed) = func(value s57.UEContextReleaseComplete,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s57.BridgeUEContextReleaseCompleteValueCodecFieldCapture(&sealed) = b.capture
		*s57.BridgeUEContextReleaseCompleteValueCodecFieldCompare(&sealed) = b.compare
		*s57.BridgeUEContextReleaseCompleteValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextReleaseCompleteSuccessfulBinding) Build(body s57.UEContextReleaseComplete,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s28.ENBConfigurationUpdateAcknowledge, aper.DecodeState,

	) (s28.ENBConfigurationUpdateAcknowledge, aper.Snapshot,

	)
	compare func(s28.ENBConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s28.ENBConfigurationUpdateAcknowledge,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s28.ENBConfigurationUpdateAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s28.ENBConfigurationUpdateAcknowledge,

		error)
	inject func(s28.ENBConfigurationUpdateAcknowledge,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateAcknowledgeSuccessfulBinding) Codec() s28.ENBConfigurationUpdateAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s28.ENBConfigurationUpdateAcknowledgeValueCodec{}
	}
	return func() s28.ENBConfigurationUpdateAcknowledgeValueCodec {
		sealed := s28.ENBConfigurationUpdateAcknowledgeValueCodec{}
		*s28.BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s28.BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldDecode(&sealed) = b.decode
		*s28.BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldEncode(&sealed) = func(value s28.ENBConfigurationUpdateAcknowledge,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s28.BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldCapture(&sealed) = b.capture
		*s28.BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldCompare(&sealed) = b.compare
		*s28.BridgeENBConfigurationUpdateAcknowledgeValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ENBConfigurationUpdateAcknowledgeSuccessfulBinding) Build(body s28.ENBConfigurationUpdateAcknowledge,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s30.MMEConfigurationUpdateAcknowledge, aper.DecodeState,

	) (s30.MMEConfigurationUpdateAcknowledge, aper.Snapshot,

	)
	compare func(s30.MMEConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s30.MMEConfigurationUpdateAcknowledge,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s30.MMEConfigurationUpdateAcknowledge,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s30.MMEConfigurationUpdateAcknowledge,

		error)
	inject func(s30.MMEConfigurationUpdateAcknowledge,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateAcknowledgeSuccessfulBinding) Codec() s30.MMEConfigurationUpdateAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s30.MMEConfigurationUpdateAcknowledgeValueCodec{}
	}
	return func() s30.MMEConfigurationUpdateAcknowledgeValueCodec {
		sealed := s30.MMEConfigurationUpdateAcknowledgeValueCodec{}
		*s30.BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s30.BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldDecode(&sealed) = b.decode
		*s30.BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldEncode(&sealed) = func(value s30.MMEConfigurationUpdateAcknowledge,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s30.BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldCapture(&sealed) = b.capture
		*s30.BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldCompare(&sealed) = b.compare
		*s30.BridgeMMEConfigurationUpdateAcknowledgeValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b MMEConfigurationUpdateAcknowledgeSuccessfulBinding) Build(body s30.MMEConfigurationUpdateAcknowledge,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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

		*aper.DecodeBudget) (s25.ValidationReport, error)
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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s42.KillResponse, aper.DecodeState,

	) (s42.KillResponse, aper.Snapshot,

	)
	compare func(s42.KillResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s42.KillResponse,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s42.KillResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s42.KillResponse,

		error)
	inject func(s42.KillResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b KillResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b KillResponseSuccessfulBinding) Codec() s42.KillResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s42.KillResponseValueCodec{}
	}
	return func() s42.KillResponseValueCodec {
		sealed := s42.KillResponseValueCodec{}
		*s42.BridgeKillResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s42.BridgeKillResponseValueCodecFieldDecode(&sealed) = b.decode
		*s42.BridgeKillResponseValueCodecFieldEncode(&sealed) = func(value s42.KillResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s42.BridgeKillResponseValueCodecFieldCapture(&sealed) = b.capture
		*s42.BridgeKillResponseValueCodecFieldCompare(&sealed) = b.compare
		*s42.BridgeKillResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b KillResponseSuccessfulBinding) Build(body s42.KillResponse,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s46.UERadioCapabilityMatchResponse, aper.DecodeState,

	) (s46.UERadioCapabilityMatchResponse, aper.Snapshot,

	)
	compare func(s46.UERadioCapabilityMatchResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s46.UERadioCapabilityMatchResponse,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s46.UERadioCapabilityMatchResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s46.UERadioCapabilityMatchResponse,

		error)
	inject func(s46.UERadioCapabilityMatchResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityMatchResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityMatchResponseSuccessfulBinding) Codec() s46.UERadioCapabilityMatchResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.UERadioCapabilityMatchResponseValueCodec{}
	}
	return func() s46.UERadioCapabilityMatchResponseValueCodec {
		sealed := s46.UERadioCapabilityMatchResponseValueCodec{}
		*s46.BridgeUERadioCapabilityMatchResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s46.BridgeUERadioCapabilityMatchResponseValueCodecFieldDecode(&sealed) = b.decode
		*s46.BridgeUERadioCapabilityMatchResponseValueCodecFieldEncode(&sealed) = func(value s46.UERadioCapabilityMatchResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s46.BridgeUERadioCapabilityMatchResponseValueCodecFieldCapture(&sealed) = b.capture
		*s46.BridgeUERadioCapabilityMatchResponseValueCodecFieldCompare(&sealed) = b.compare
		*s46.BridgeUERadioCapabilityMatchResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UERadioCapabilityMatchResponseSuccessfulBinding) Build(body s46.UERadioCapabilityMatchResponse,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s49.ERABModificationConfirm, aper.DecodeState,

	) (s49.ERABModificationConfirm, aper.Snapshot,

	)
	compare func(s49.ERABModificationConfirm, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s49.ERABModificationConfirm,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s49.ERABModificationConfirm,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s49.ERABModificationConfirm,

		error)
	inject func(s49.ERABModificationConfirm,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ERABModificationConfirmSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ERABModificationConfirmSuccessfulBinding) Codec() s49.ERABModificationConfirmValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s49.ERABModificationConfirmValueCodec{}
	}
	return func() s49.ERABModificationConfirmValueCodec {
		sealed := s49.ERABModificationConfirmValueCodec{}
		*s49.BridgeERABModificationConfirmValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s49.BridgeERABModificationConfirmValueCodecFieldDecode(&sealed) = b.decode
		*s49.BridgeERABModificationConfirmValueCodecFieldEncode(&sealed) = func(value s49.ERABModificationConfirm,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s49.BridgeERABModificationConfirmValueCodecFieldCapture(&sealed) = b.capture
		*s49.BridgeERABModificationConfirmValueCodecFieldCompare(&sealed) = b.compare
		*s49.BridgeERABModificationConfirmValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ERABModificationConfirmSuccessfulBinding) Build(body s49.ERABModificationConfirm,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s45.UEContextModificationConfirm, aper.DecodeState,

	) (s45.UEContextModificationConfirm, aper.Snapshot,

	)
	compare func(s45.UEContextModificationConfirm, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s45.UEContextModificationConfirm,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s45.UEContextModificationConfirm,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s45.UEContextModificationConfirm,

		error)
	inject func(s45.UEContextModificationConfirm,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationConfirmSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationConfirmSuccessfulBinding) Codec() s45.UEContextModificationConfirmValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s45.UEContextModificationConfirmValueCodec{}
	}
	return func() s45.UEContextModificationConfirmValueCodec {
		sealed := s45.UEContextModificationConfirmValueCodec{}
		*s45.BridgeUEContextModificationConfirmValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s45.BridgeUEContextModificationConfirmValueCodecFieldDecode(&sealed) = b.decode
		*s45.BridgeUEContextModificationConfirmValueCodecFieldEncode(&sealed) = func(value s45.UEContextModificationConfirm,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s45.BridgeUEContextModificationConfirmValueCodecFieldCapture(&sealed) = b.capture
		*s45.BridgeUEContextModificationConfirmValueCodecFieldCompare(&sealed) = b.compare
		*s45.BridgeUEContextModificationConfirmValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextModificationConfirmSuccessfulBinding) Build(body s45.UEContextModificationConfirm,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s46.UEContextSuspendResponse, aper.DecodeState,

	) (s46.UEContextSuspendResponse, aper.Snapshot,

	)
	compare func(s46.UEContextSuspendResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s46.UEContextSuspendResponse,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s46.UEContextSuspendResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s46.UEContextSuspendResponse,

		error)
	inject func(s46.UEContextSuspendResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextSuspendResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextSuspendResponseSuccessfulBinding) Codec() s46.UEContextSuspendResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.UEContextSuspendResponseValueCodec{}
	}
	return func() s46.UEContextSuspendResponseValueCodec {
		sealed := s46.UEContextSuspendResponseValueCodec{}
		*s46.BridgeUEContextSuspendResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s46.BridgeUEContextSuspendResponseValueCodecFieldDecode(&sealed) = b.decode
		*s46.BridgeUEContextSuspendResponseValueCodecFieldEncode(&sealed) = func(value s46.UEContextSuspendResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s46.BridgeUEContextSuspendResponseValueCodecFieldCapture(&sealed) = b.capture
		*s46.BridgeUEContextSuspendResponseValueCodecFieldCompare(&sealed) = b.compare
		*s46.BridgeUEContextSuspendResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextSuspendResponseSuccessfulBinding) Build(body s46.UEContextSuspendResponse,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s49.UEContextResumeResponse, aper.DecodeState,

	) (s49.UEContextResumeResponse, aper.Snapshot,

	)
	compare func(s49.UEContextResumeResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s49.UEContextResumeResponse,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s49.UEContextResumeResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s49.UEContextResumeResponse,

		error)
	inject func(s49.UEContextResumeResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeResponseSuccessfulBinding) Codec() s49.UEContextResumeResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s49.UEContextResumeResponseValueCodec{}
	}
	return func() s49.UEContextResumeResponseValueCodec {
		sealed := s49.UEContextResumeResponseValueCodec{}
		*s49.BridgeUEContextResumeResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s49.BridgeUEContextResumeResponseValueCodecFieldDecode(&sealed) = b.decode
		*s49.BridgeUEContextResumeResponseValueCodecFieldEncode(&sealed) = func(value s49.UEContextResumeResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s49.BridgeUEContextResumeResponseValueCodecFieldCapture(&sealed) = b.capture
		*s49.BridgeUEContextResumeResponseValueCodecFieldCompare(&sealed) = b.compare
		*s49.BridgeUEContextResumeResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextResumeResponseSuccessfulBinding) Build(body s49.UEContextResumeResponse,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s46.UERadioCapabilityIDMappingResponse, aper.DecodeState,

	) (s46.UERadioCapabilityIDMappingResponse, aper.Snapshot,

	)
	compare func(s46.UERadioCapabilityIDMappingResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s46.UERadioCapabilityIDMappingResponse,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s46.UERadioCapabilityIDMappingResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s46.UERadioCapabilityIDMappingResponse,

		error)
	inject func(s46.UERadioCapabilityIDMappingResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UERadioCapabilityIDMappingResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UERadioCapabilityIDMappingResponseSuccessfulBinding) Codec() s46.UERadioCapabilityIDMappingResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s46.UERadioCapabilityIDMappingResponseValueCodec{}
	}
	return func() s46.UERadioCapabilityIDMappingResponseValueCodec {
		sealed := s46.UERadioCapabilityIDMappingResponseValueCodec{}
		*s46.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s46.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldDecode(&sealed) = b.decode
		*s46.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldEncode(&sealed) = func(value s46.UERadioCapabilityIDMappingResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s46.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldCapture(&sealed) = b.capture
		*s46.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldCompare(&sealed) = b.compare
		*s46.BridgeUERadioCapabilityIDMappingResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UERadioCapabilityIDMappingResponseSuccessfulBinding) Build(body s46.UERadioCapabilityIDMappingResponse,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s31.S1RemovalResponse, aper.DecodeState,

	) (s31.S1RemovalResponse, aper.Snapshot,

	)
	compare func(s31.S1RemovalResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s31.S1RemovalResponse,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s31.S1RemovalResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s31.S1RemovalResponse,

		error)
	inject func(s31.S1RemovalResponse,

	) SuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b S1RemovalResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1RemovalResponseSuccessfulBinding) Codec() s31.S1RemovalResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s31.S1RemovalResponseValueCodec{}
	}
	return func() s31.S1RemovalResponseValueCodec {
		sealed := s31.S1RemovalResponseValueCodec{}
		*s31.BridgeS1RemovalResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s31.BridgeS1RemovalResponseValueCodecFieldDecode(&sealed) = b.decode
		*s31.BridgeS1RemovalResponseValueCodecFieldEncode(&sealed) = func(value s31.S1RemovalResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s31.BridgeS1RemovalResponseValueCodecFieldCapture(&sealed) = b.capture
		*s31.BridgeS1RemovalResponseValueCodecFieldCompare(&sealed) = b.compare
		*s31.BridgeS1RemovalResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1RemovalResponseSuccessfulBinding) Build(body s31.S1RemovalResponse,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
func BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEContainer(v *s42.WriteReplaceWarningRequestIEContainer, s *aper.SemanticCapture) {
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
func BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEContainer(v *s42.WriteReplaceWarningRequestIEContainer, s *aper.SemanticComparison) {
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
func BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEContainer(v *s41.WriteReplaceWarningResponseIEContainer, s *aper.SemanticCapture) {
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
func BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEContainer(v *s41.WriteReplaceWarningResponseIEContainer, s *aper.SemanticComparison) {
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
func BridgeX2TNLConfigurationInfoExtIEsValueCaptureS1APProtocolExtensionContainer(v *s48.X2TNLConfigurationInfoExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeX2TNLConfigurationInfoExtIEsValueCompareS1APProtocolExtensionContainer(v *s48.X2TNLConfigurationInfoExtIEsExtContainer, s *aper.SemanticComparison) {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(65535), false); err != nil {
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
	codec  s40.SynchronisationInformationValueCodec
	inject func(s40.SynchronisationInformation,

	) SONConfigurationTransferExtIEsValue

	get func(*SONConfigurationTransferExtIEsValue,

	) (*s40.SynchronisationInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SONConfigurationTransferExtIEsSynchronisationInformationExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SONConfigurationTransferExtIEsSynchronisationInformationExtBinding) Codec() s40.SynchronisationInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SONConfigurationTransferExtIEsSynchronisationInformationExtBinding) New(value s40.SynchronisationInformation,

) (SONConfigurationTransferExtIEsExtField, error) {
	if b.inject == nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s40.BridgeSynchronisationInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SONConfigurationTransferExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SONConfigurationTransferExtIEsSynchronisationInformationExtBinding) Get(field *SONConfigurationTransferExtIEsExtField) (*s40.SynchronisationInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding binds RequestedTNLInfo to the SONConfigurationTransfer-ExtIEs object set of TS 36.413.
type SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding struct {
	info   s00.ExtensionInfo
	codec  s31.RequestedTNLInfoValueCodec
	inject func(s31.RequestedTNLInfo,

	) SONConfigurationTransferExtIEsValue

	get func(*SONConfigurationTransferExtIEsValue,

	) (*s31.RequestedTNLInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding) Info() s00.ExtensionInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding) Codec() s31.RequestedTNLInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding) New(value s31.RequestedTNLInfo,

) (SONConfigurationTransferExtIEsExtField, error) {
	if b.inject == nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeRequestedTNLInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return SONConfigurationTransferExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return SONConfigurationTransferExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding) Get(field *SONConfigurationTransferExtIEsExtField) (*s31.RequestedTNLInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// SONConfigurationTransferValueCodec is the concrete ValueCodec[SONConfigurationTransfer].
type SONConfigurationTransferValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (SONConfigurationTransfer,

		error)
	encode func(SONConfigurationTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(SONConfigurationTransfer, aper.DecodeState,

	) (SONConfigurationTransfer, aper.Snapshot,

	)
	compare func(SONConfigurationTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONConfigurationTransferValueCodec) New(value SONConfigurationTransfer,

) (SONConfigurationTransferAPERValue, error) {
	if c.encode == nil {
		return SONConfigurationTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONConfigurationTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONConfigurationTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONConfigurationTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONConfigurationTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONConfigurationTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONConfigurationTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONConfigurationTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONConfigurationTransferAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONConfigurationTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONConfigurationTransferValueCodec) EncodeAPER(value SONConfigurationTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SONConfigurationTransferValueCodec) encodeBudgetValue(value SONConfigurationTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONConfigurationTransferValueCodec) encodeChanged(value SONConfigurationTransfer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
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

// MMEConfigurationTransferENDCSONConfigurationTransferIEBinding binds ENDCSONConfigurationTransfer to the MMEConfigurationTransferIEs object set of TS 36.413.
type MMEConfigurationTransferENDCSONConfigurationTransferIEBinding struct {
	info   s00.FieldInfo
	codec  ENDCSONConfigurationTransferValueCodec
	inject func(ENDCSONConfigurationTransfer,

	) MMEConfigurationTransferIEValue

	get func(*MMEConfigurationTransferIEValue,

	) (*ENDCSONConfigurationTransfer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationTransferENDCSONConfigurationTransferIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationTransferENDCSONConfigurationTransferIEBinding) Codec() ENDCSONConfigurationTransferValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEConfigurationTransferENDCSONConfigurationTransferIEBinding) New(value ENDCSONConfigurationTransfer,

) (MMEConfigurationTransferIEField, error) {
	if b.inject == nil {
		return MMEConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return MMEConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEConfigurationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEConfigurationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationTransferENDCSONConfigurationTransferIEBinding) Get(field *MMEConfigurationTransferIEField) (*ENDCSONConfigurationTransfer,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MMEConfigurationTransferIntersystemSONConfigurationTransferIEBinding binds IntersystemSONConfigurationTransfer to the MMEConfigurationTransferIEs object set of TS 36.413.
type MMEConfigurationTransferIntersystemSONConfigurationTransferIEBinding struct {
	info   s00.FieldInfo
	codec  s01.IntersystemSONConfigurationTransferValueCodec
	inject func(s00.IntersystemSONConfigurationTransfer,

	) MMEConfigurationTransferIEValue

	get func(*MMEConfigurationTransferIEValue,

	) (*s00.IntersystemSONConfigurationTransfer,

		bool)
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationTransferIntersystemSONConfigurationTransferIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationTransferIntersystemSONConfigurationTransferIEBinding) Codec() s01.IntersystemSONConfigurationTransferValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b MMEConfigurationTransferIntersystemSONConfigurationTransferIEBinding) New(value s00.IntersystemSONConfigurationTransfer,

) (MMEConfigurationTransferIEField, error) {
	if b.inject == nil {
		return MMEConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeIntersystemSONConfigurationTransferValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return MMEConfigurationTransferIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MMEConfigurationTransferIEField{}, aper.OperationError(err, "Value.New")
	}
	return MMEConfigurationTransferIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b MMEConfigurationTransferIntersystemSONConfigurationTransferIEBinding) Get(field *MMEConfigurationTransferIEField) (*s00.IntersystemSONConfigurationTransfer,

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
func BridgeWriteReplaceWarningRequestIEValueValidateS1APIEContainer(fields s42.WriteReplaceWarningRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s42.BridgeWriteReplaceWarningRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s42.BridgeWriteReplaceWarningRequestIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s42.BridgeWriteReplaceWarningRequestIEValueMethodRule(field.Value).Assignment
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
func BridgeWriteReplaceWarningResponseIEValueValidateS1APIEContainer(fields s41.WriteReplaceWarningResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s41.BridgeWriteReplaceWarningResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s41.BridgeWriteReplaceWarningResponseIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s41.BridgeWriteReplaceWarningResponseIEValueMethodRule(field.Value).Assignment
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

// WriteReplaceWarningRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{WriteReplaceWarningRequestIEs}} codec of TS 36.413.
func WriteReplaceWarningRequestIEValueERABIEContainerListCodec(table s00.WriteReplaceWarningRequestIEValueIETable) s42.WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec {
	codec := WriteReplaceWarningRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s42.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s42.WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s42.WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec {
		sealed := s42.WriteReplaceWarningRequestIEValueERABIEContainerListValueCodec{}
		*s42.BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "WriteReplaceWarningRequestIEValueERABIEContainerList"
		*s42.BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s42.WriteReplaceWarningRequestIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s42.WriteReplaceWarningRequestIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s42.WriteReplaceWarningRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s42.BridgeWriteReplaceWarningRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s42.BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s42.WriteReplaceWarningRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s42.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldEncode(&codec))(s42.WriteReplaceWarningRequestIEContainer(value), fresh, budget)
		}
		*s42.BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s42.WriteReplaceWarningRequestIEValueERABIEContainerList, options aper.DecodeState) (s42.WriteReplaceWarningRequestIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s42.BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s42.WriteReplaceWarningRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s42.BridgeWriteReplaceWarningRequestIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{WriteReplaceWarningResponseIEs}} codec of TS 36.413.
func WriteReplaceWarningResponseIEValueERABIEContainerListCodec(table s00.WriteReplaceWarningResponseIEValueIETable) s41.WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec {
	codec := WriteReplaceWarningResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s41.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s41.WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s41.WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec {
		sealed := s41.WriteReplaceWarningResponseIEValueERABIEContainerListValueCodec{}
		*s41.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "WriteReplaceWarningResponseIEValueERABIEContainerList"
		*s41.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.WriteReplaceWarningResponseIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s41.WriteReplaceWarningResponseIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s41.WriteReplaceWarningResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s41.BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s41.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s41.WriteReplaceWarningResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s41.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldEncode(&codec))(s41.WriteReplaceWarningResponseIEContainer(value), fresh, budget)
		}
		*s41.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s41.WriteReplaceWarningResponseIEValueERABIEContainerList, options aper.DecodeState) (s41.WriteReplaceWarningResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s41.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s41.WriteReplaceWarningResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s41.BridgeWriteReplaceWarningResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	return SONConfigurationTransferExtIEsExtFieldValueCodec{path: "SONConfigurationTransferExtIEsExtField", decode: func(data []byte, options aper.DecodeState) (SONConfigurationTransferExtIEsExtField, error) {
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
func X2TNLConfigurationInfoExtIEsValueExtensionFieldTableCodec(table s00.X2TNLConfigurationInfoExtIEsValueExtensionTable) s48.X2TNLConfigurationInfoExtIEsExtFieldValueCodec {
	if !*s00.BridgeX2TNLConfigurationInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s48.X2TNLConfigurationInfoExtIEsExtFieldValueCodec{}
	}
	return func() s48.X2TNLConfigurationInfoExtIEsExtFieldValueCodec {
		sealed := s48.X2TNLConfigurationInfoExtIEsExtFieldValueCodec{}
		*s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldPath(&sealed) = "X2TNLConfigurationInfoExtIEsExtField"
		*s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s48.X2TNLConfigurationInfoExtIEsExtField, error) {
			var field s48.X2TNLConfigurationInfoExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "X2TNLConfigurationInfoExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "X2TNLConfigurationInfoExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "X2TNLConfigurationInfoExtIEsExtField")
			}
			return field, nil
		}
		*s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s48.X2TNLConfigurationInfoExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s48.X2TNLConfigurationInfoExtIEsExtField, options aper.DecodeState) (s48.X2TNLConfigurationInfoExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeX2TNLConfigurationInfoExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s48.X2TNLConfigurationInfoExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeX2TNLConfigurationInfoExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// SONConfigurationTransferExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{SONConfigurationTransfer-ExtIEs}} codec of TS 36.413.
func SONConfigurationTransferExtIEsValueExtensionTableCodec(table s00.SONConfigurationTransferExtIEsValueExtensionTable, bounds aper.ListBounds) SONConfigurationTransferExtIEsExtContainerValueCodec {
	if !*s00.BridgeSONConfigurationTransferExtIEsValueExtensionTableFieldBound(&table) {
		return SONConfigurationTransferExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return SONConfigurationTransferExtIEsExtContainerValueCodec{path: "SONConfigurationTransferExtIEsExtContainer", decode: func(data []byte, options aper.DecodeState) (SONConfigurationTransferExtIEsExtContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields SONConfigurationTransferExtIEsExtContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field SONConfigurationTransferExtIEsExtField
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
			return nil, runtime.WrapDecodePath(err, "SONConfigurationTransferExtIEsExtContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "SONConfigurationTransferExtIEsExtContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "SONConfigurationTransferExtIEsExtContainer")
		}
		return fields, nil
	},
		encode: func(fields SONConfigurationTransferExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v SONConfigurationTransferExtIEsExtContainer, options aper.DecodeState) (SONConfigurationTransferExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}, compare: func(v SONConfigurationTransferExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}

// X2TNLConfigurationInfoExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{X2TNLConfigurationInfo-ExtIEs}} codec of TS 36.413.
func X2TNLConfigurationInfoExtIEsValueExtensionTableCodec(table s00.X2TNLConfigurationInfoExtIEsValueExtensionTable, bounds aper.ListBounds) s48.X2TNLConfigurationInfoExtIEsExtContainerValueCodec {
	if !*s00.BridgeX2TNLConfigurationInfoExtIEsValueExtensionTableFieldBound(&table) {
		return s48.X2TNLConfigurationInfoExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s48.X2TNLConfigurationInfoExtIEsExtContainerValueCodec {
		sealed := s48.X2TNLConfigurationInfoExtIEsExtContainerValueCodec{}
		*s48.BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldPath(&sealed) = "X2TNLConfigurationInfoExtIEsExtContainer"
		*s48.BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s48.X2TNLConfigurationInfoExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s48.X2TNLConfigurationInfoExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s48.X2TNLConfigurationInfoExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s48.BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s48.X2TNLConfigurationInfoExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s48.BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s48.X2TNLConfigurationInfoExtIEsExtContainer, options aper.DecodeState) (s48.X2TNLConfigurationInfoExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeX2TNLConfigurationInfoExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s48.BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s48.X2TNLConfigurationInfoExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeX2TNLConfigurationInfoExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s48.BridgeX2TNLConfigurationInfoExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{WriteReplaceWarningRequestIEs}} codec of TS 36.413.
func WriteReplaceWarningRequestIEValueIEFieldTableCodec(table s00.WriteReplaceWarningRequestIEValueIETable) s42.WriteReplaceWarningRequestIEFieldValueCodec {
	if !*s00.BridgeWriteReplaceWarningRequestIEValueIETableFieldBound(&table) {
		return s42.WriteReplaceWarningRequestIEFieldValueCodec{}
	}
	return func() s42.WriteReplaceWarningRequestIEFieldValueCodec {
		sealed := s42.WriteReplaceWarningRequestIEFieldValueCodec{}
		*s42.BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldPath(&sealed) = "WriteReplaceWarningRequestIEField"
		*s42.BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s42.WriteReplaceWarningRequestIEField, error) {
			var field s42.WriteReplaceWarningRequestIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s42.BridgeWriteReplaceWarningRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "WriteReplaceWarningRequestIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "WriteReplaceWarningRequestIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "WriteReplaceWarningRequestIEField")
			}
			return field, nil
		}
		*s42.BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldEncode(&sealed) = func(field s42.WriteReplaceWarningRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s42.BridgeWriteReplaceWarningRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s42.BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldCapture(&sealed) = func(v s42.WriteReplaceWarningRequestIEField, options aper.DecodeState) (s42.WriteReplaceWarningRequestIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s42.BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldCompare(&sealed) = func(v s42.WriteReplaceWarningRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s42.BridgeWriteReplaceWarningRequestIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{WriteReplaceWarningResponseIEs}} codec of TS 36.413.
func WriteReplaceWarningResponseIEValueIEFieldTableCodec(table s00.WriteReplaceWarningResponseIEValueIETable) s41.WriteReplaceWarningResponseIEFieldValueCodec {
	if !*s00.BridgeWriteReplaceWarningResponseIEValueIETableFieldBound(&table) {
		return s41.WriteReplaceWarningResponseIEFieldValueCodec{}
	}
	return func() s41.WriteReplaceWarningResponseIEFieldValueCodec {
		sealed := s41.WriteReplaceWarningResponseIEFieldValueCodec{}
		*s41.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldPath(&sealed) = "WriteReplaceWarningResponseIEField"
		*s41.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.WriteReplaceWarningResponseIEField, error) {
			var field s41.WriteReplaceWarningResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s41.BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "WriteReplaceWarningResponseIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "WriteReplaceWarningResponseIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "WriteReplaceWarningResponseIEField")
			}
			return field, nil
		}
		*s41.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s41.WriteReplaceWarningResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s41.BridgeWriteReplaceWarningResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s41.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s41.WriteReplaceWarningResponseIEField, options aper.DecodeState) (s41.WriteReplaceWarningResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s41.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s41.WriteReplaceWarningResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s41.BridgeWriteReplaceWarningResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningRequestIEValueIETableCodec constructs the ProtocolIE-Container {{WriteReplaceWarningRequestIEs}} codec of TS 36.413.
func WriteReplaceWarningRequestIEValueIETableCodec(table s00.WriteReplaceWarningRequestIEValueIETable, bounds aper.ListBounds) s42.WriteReplaceWarningRequestIEContainerValueCodec {
	if !*s00.BridgeWriteReplaceWarningRequestIEValueIETableFieldBound(&table) {
		return s42.WriteReplaceWarningRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s42.WriteReplaceWarningRequestIEContainerValueCodec {
		sealed := s42.WriteReplaceWarningRequestIEContainerValueCodec{}
		*s42.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldPath(&sealed) = "WriteReplaceWarningRequestIEContainer"
		*s42.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s42.WriteReplaceWarningRequestIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s42.WriteReplaceWarningRequestIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s42.WriteReplaceWarningRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s42.BridgeWriteReplaceWarningRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s42.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldEncode(&sealed) = func(fields s42.WriteReplaceWarningRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s42.BridgeWriteReplaceWarningRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s42.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldCapture(&sealed) = func(v s42.WriteReplaceWarningRequestIEContainer, options aper.DecodeState) (s42.WriteReplaceWarningRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s42.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldCompare(&sealed) = func(v s42.WriteReplaceWarningRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s42.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningResponseIEValueIETableCodec constructs the ProtocolIE-Container {{WriteReplaceWarningResponseIEs}} codec of TS 36.413.
func WriteReplaceWarningResponseIEValueIETableCodec(table s00.WriteReplaceWarningResponseIEValueIETable, bounds aper.ListBounds) s41.WriteReplaceWarningResponseIEContainerValueCodec {
	if !*s00.BridgeWriteReplaceWarningResponseIEValueIETableFieldBound(&table) {
		return s41.WriteReplaceWarningResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s41.WriteReplaceWarningResponseIEContainerValueCodec {
		sealed := s41.WriteReplaceWarningResponseIEContainerValueCodec{}
		*s41.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldPath(&sealed) = "WriteReplaceWarningResponseIEContainer"
		*s41.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.WriteReplaceWarningResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s41.WriteReplaceWarningResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s41.WriteReplaceWarningResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s41.BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s41.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s41.WriteReplaceWarningResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s41.BridgeWriteReplaceWarningResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s41.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s41.WriteReplaceWarningResponseIEContainer, options aper.DecodeState) (s41.WriteReplaceWarningResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s41.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s41.WriteReplaceWarningResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s41.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{WriteReplaceWarningRequestIEs}} codec of TS 36.413.
func WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListCodec(table s00.WriteReplaceWarningRequestIEValueIETable) s42.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := WriteReplaceWarningRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s42.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s42.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s42.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s42.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodec{}
		*s42.BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList"
		*s42.BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s42.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s42.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s42.WriteReplaceWarningRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s42.BridgeWriteReplaceWarningRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s42.BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s42.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s42.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldEncode(&codec))(s42.WriteReplaceWarningRequestIEContainer(value), fresh, budget)
		}
		*s42.BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s42.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s42.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s42.BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s42.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s42.BridgeWriteReplaceWarningRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{WriteReplaceWarningResponseIEs}} codec of TS 36.413.
func WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListCodec(table s00.WriteReplaceWarningResponseIEValueIETable) s41.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := WriteReplaceWarningResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s41.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s41.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s41.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s41.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s41.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList"
		*s41.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s41.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s41.WriteReplaceWarningResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s41.BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s41.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s41.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s41.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldEncode(&codec))(s41.WriteReplaceWarningResponseIEContainer(value), fresh, budget)
		}
		*s41.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s41.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s41.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s41.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s41.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s41.BridgeWriteReplaceWarningResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {WriteReplaceWarningRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func WriteReplaceWarningRequestIEValueProtocolIEContainerListCodec(table s00.WriteReplaceWarningRequestIEValueIETable, bounds aper.ListBounds) s42.WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec {
	codec := WriteReplaceWarningRequestIEValueIETableCodec(table, bounds)
	if *s42.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s42.WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s42.WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec {
		sealed := s42.WriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodec{}
		*s42.BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "WriteReplaceWarningRequestIEValueProtocolIEContainerList"
		*s42.BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s42.WriteReplaceWarningRequestIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s42.WriteReplaceWarningRequestIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s42.WriteReplaceWarningRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s42.BridgeWriteReplaceWarningRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s42.BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s42.WriteReplaceWarningRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s42.BridgeWriteReplaceWarningRequestIEContainerValueCodecFieldEncode(&codec))(s42.WriteReplaceWarningRequestIEContainer(value), fresh, budget)
		}
		*s42.BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s42.WriteReplaceWarningRequestIEValueProtocolIEContainerList, options aper.DecodeState) (s42.WriteReplaceWarningRequestIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s42.BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s42.WriteReplaceWarningRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s42.BridgeWriteReplaceWarningRequestIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// WriteReplaceWarningResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {WriteReplaceWarningResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func WriteReplaceWarningResponseIEValueProtocolIEContainerListCodec(table s00.WriteReplaceWarningResponseIEValueIETable, bounds aper.ListBounds) s41.WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec {
	codec := WriteReplaceWarningResponseIEValueIETableCodec(table, bounds)
	if *s41.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s41.WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s41.WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s41.WriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodec{}
		*s41.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "WriteReplaceWarningResponseIEValueProtocolIEContainerList"
		*s41.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s41.WriteReplaceWarningResponseIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s41.WriteReplaceWarningResponseIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s41.WriteReplaceWarningResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s41.BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s41.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s41.WriteReplaceWarningResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s41.BridgeWriteReplaceWarningResponseIEContainerValueCodecFieldEncode(&codec))(s41.WriteReplaceWarningResponseIEContainer(value), fresh, budget)
		}
		*s41.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s41.WriteReplaceWarningResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s41.WriteReplaceWarningResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s41.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s41.WriteReplaceWarningResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s41.BridgeWriteReplaceWarningResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// writeReplaceWarningRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[WriteReplaceWarningRequestIEValue].
type WriteReplaceWarningRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s42.WriteReplaceWarningRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s42.WriteReplaceWarningRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEField(v *s42.WriteReplaceWarningRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s42.BridgeWriteReplaceWarningRequestIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s42.BridgeWriteReplaceWarningRequestIEFieldFieldReplay(v), *s42.BridgeWriteReplaceWarningRequestIEFieldFieldWithoutReplay(v))
}
func BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEField(v *s42.WriteReplaceWarningRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s42.BridgeWriteReplaceWarningRequestIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s42.BridgeWriteReplaceWarningRequestIEFieldFieldReplay(v), *s42.BridgeWriteReplaceWarningRequestIEFieldFieldWithoutReplay(v))
}

// writeReplaceWarningResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[WriteReplaceWarningResponseIEValue].
type WriteReplaceWarningResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s41.WriteReplaceWarningResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s41.WriteReplaceWarningResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEField(v *s41.WriteReplaceWarningResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s41.BridgeWriteReplaceWarningResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s41.BridgeWriteReplaceWarningResponseIEFieldFieldReplay(v), *s41.BridgeWriteReplaceWarningResponseIEFieldFieldWithoutReplay(v))
}
func BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEField(v *s41.WriteReplaceWarningResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s41.BridgeWriteReplaceWarningResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s41.BridgeWriteReplaceWarningResponseIEFieldFieldReplay(v), *s41.BridgeWriteReplaceWarningResponseIEFieldFieldWithoutReplay(v))
}
func BridgeX2TNLConfigurationInfoExtIEsValueCaptureS1APProtocolExtensionField(v *s48.X2TNLConfigurationInfoExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s48.BridgeX2TNLConfigurationInfoExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldFieldReplay(v), *s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeX2TNLConfigurationInfoExtIEsValueCompareS1APProtocolExtensionField(v *s48.X2TNLConfigurationInfoExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s48.BridgeX2TNLConfigurationInfoExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldFieldReplay(v), *s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldFieldWithoutReplay(v))
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

// SONConfigurationTransferAPERValue is the concrete APERValue[SONConfigurationTransfer].
type SONConfigurationTransferAPERValue struct {
	context s00.BridgeCodecContext
	Value   SONConfigurationTransfer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONConfigurationTransferAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONConfigurationTransferAPERValue) WithoutReplay() SONConfigurationTransferAPERValue {
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

// MMEConfigurationTransferIEValueERABIEContainerListValueCodec is the concrete ValueCodec[MMEConfigurationTransferIEValueERABIEContainerList].
type MMEConfigurationTransferIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationTransferIEValueERABIEContainerList, error)
	encode  func(MMEConfigurationTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationTransferIEValueERABIEContainerList, aper.DecodeState) (MMEConfigurationTransferIEValueERABIEContainerList, aper.Snapshot)
	compare func(MMEConfigurationTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationTransferIEValueERABIEContainerListValueCodec) New(value MMEConfigurationTransferIEValueERABIEContainerList) (MMEConfigurationTransferIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationTransferIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationTransferIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationTransferIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationTransferIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationTransferIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationTransferIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationTransferIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationTransferIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationTransferIEValueERABIEContainerListValueCodec) EncodeAPER(value MMEConfigurationTransferIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEConfigurationTransferIEValueERABIEContainerListValueCodec) encodeBudgetValue(value MMEConfigurationTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationTransferIEValueERABIEContainerListValueCodec) encodeChanged(value MMEConfigurationTransferIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationTransferIEValueERABIEContainerList is E-RAB-IE-ContainerList {{MMEConfigurationTransferIEs}} of TS 36.413: a list of information element fields.
type MMEConfigurationTransferIEValueERABIEContainerList []MMEConfigurationTransferIEValueProtocolIESingleContainer

func BridgeWriteReplaceWarningRequestIEValueCaptureS1APERABIEContainerList(v *s42.WriteReplaceWarningRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
func BridgeWriteReplaceWarningRequestIEValueCompareS1APERABIEContainerList(v *s42.WriteReplaceWarningRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
func BridgeWriteReplaceWarningResponseIEValueCaptureS1APERABIEContainerList(v *s41.WriteReplaceWarningResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
func BridgeWriteReplaceWarningResponseIEValueCompareS1APERABIEContainerList(v *s41.WriteReplaceWarningResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
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

// MMEConfigurationTransferIEFieldValueCodec is the concrete ValueCodec[MMEConfigurationTransferIEField].
type MMEConfigurationTransferIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationTransferIEField, error)
	encode  func(MMEConfigurationTransferIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationTransferIEField, aper.DecodeState) (MMEConfigurationTransferIEField, aper.Snapshot)
	compare func(MMEConfigurationTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationTransferIEFieldValueCodec) New(value MMEConfigurationTransferIEField) (MMEConfigurationTransferIEFieldAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationTransferIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationTransferIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationTransferIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationTransferIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationTransferIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationTransferIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationTransferIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationTransferIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationTransferIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationTransferIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationTransferIEFieldValueCodec) EncodeAPER(value MMEConfigurationTransferIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEConfigurationTransferIEFieldValueCodec) encodeBudgetValue(value MMEConfigurationTransferIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationTransferIEFieldValueCodec) encodeChanged(value MMEConfigurationTransferIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
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

// MMEConfigurationTransferIEContainerValueCodec is the concrete ValueCodec[MMEConfigurationTransferIEContainer].
type MMEConfigurationTransferIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationTransferIEContainer, error)
	encode  func(MMEConfigurationTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationTransferIEContainer, aper.DecodeState) (MMEConfigurationTransferIEContainer, aper.Snapshot)
	compare func(MMEConfigurationTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationTransferIEContainerValueCodec) New(value MMEConfigurationTransferIEContainer) (MMEConfigurationTransferIEContainerAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationTransferIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationTransferIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationTransferIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationTransferIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationTransferIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationTransferIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationTransferIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationTransferIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationTransferIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationTransferIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationTransferIEContainerValueCodec) EncodeAPER(value MMEConfigurationTransferIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEConfigurationTransferIEContainerValueCodec) encodeBudgetValue(value MMEConfigurationTransferIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationTransferIEContainerValueCodec) encodeChanged(value MMEConfigurationTransferIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
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

// MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[MMEConfigurationTransferIEValueProtocolErrorIEContainerList].
type MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationTransferIEValueProtocolErrorIEContainerList, error)
	encode  func(MMEConfigurationTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEConfigurationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(MMEConfigurationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) New(value MMEConfigurationTransferIEValueProtocolErrorIEContainerList) (MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value MMEConfigurationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value MMEConfigurationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationTransferIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{MMEConfigurationTransferIEs}} of TS 36.413: a list of information element fields.
type MMEConfigurationTransferIEValueProtocolErrorIEContainerList []MMEConfigurationTransferIEValueProtocolIESingleContainer

func BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *s42.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
func BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolErrorIEContainerList(v *s42.WriteReplaceWarningRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
func BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s41.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
func BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s41.WriteReplaceWarningResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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

// MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[MMEConfigurationTransferIEValueProtocolIEContainerList].
type MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (MMEConfigurationTransferIEValueProtocolIEContainerList, error)
	encode  func(MMEConfigurationTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(MMEConfigurationTransferIEValueProtocolIEContainerList, aper.DecodeState) (MMEConfigurationTransferIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(MMEConfigurationTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec) New(value MMEConfigurationTransferIEValueProtocolIEContainerList) (MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec) EncodeAPER(value MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value MMEConfigurationTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec) encodeChanged(value MMEConfigurationTransferIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEConfigurationTransferIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {MMEConfigurationTransferIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type MMEConfigurationTransferIEValueProtocolIEContainerList []MMEConfigurationTransferIEValueProtocolIESingleContainer

func BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEContainerList(v *s42.WriteReplaceWarningRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
func BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEContainerList(v *s42.WriteReplaceWarningRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
func BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEContainerList(v *s41.WriteReplaceWarningResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
func BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIEContainerList(v *s41.WriteReplaceWarningResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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

// MMEConfigurationTransferIEValueERABIEContainerListAPERValue is the concrete APERValue[MMEConfigurationTransferIEValueERABIEContainerList].
type MMEConfigurationTransferIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationTransferIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationTransferIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationTransferIEValueERABIEContainerListAPERValue) WithoutReplay() MMEConfigurationTransferIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEConfigurationTransferIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{MMEConfigurationTransferIEs}} of TS 36.413: a single information element field.
type MMEConfigurationTransferIEValueProtocolIESingleContainer = MMEConfigurationTransferIEField

func BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIESingleContainer(v *s42.WriteReplaceWarningRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeWriteReplaceWarningRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIESingleContainer(v *s42.WriteReplaceWarningRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeWriteReplaceWarningRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIESingleContainer(v *s41.WriteReplaceWarningResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeWriteReplaceWarningResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeWriteReplaceWarningResponseIEValueCompareS1APProtocolIESingleContainer(v *s41.WriteReplaceWarningResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
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

// MMEConfigurationTransferIEFieldAPERValue is the concrete APERValue[MMEConfigurationTransferIEField].
type MMEConfigurationTransferIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationTransferIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationTransferIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationTransferIEFieldAPERValue) WithoutReplay() MMEConfigurationTransferIEFieldAPERValue {
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

// MMEConfigurationTransferIEContainerAPERValue is the concrete APERValue[MMEConfigurationTransferIEContainer].
type MMEConfigurationTransferIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationTransferIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationTransferIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationTransferIEContainerAPERValue) WithoutReplay() MMEConfigurationTransferIEContainerAPERValue {
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

// MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[MMEConfigurationTransferIEValueProtocolErrorIEContainerList].
type MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationTransferIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() MMEConfigurationTransferIEValueProtocolErrorIEContainerListAPERValue {
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

// MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue is the concrete APERValue[MMEConfigurationTransferIEValueProtocolIEContainerList].
type MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         MMEConfigurationTransferIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue) WithoutReplay() MMEConfigurationTransferIEValueProtocolIEContainerListAPERValue {
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
	bodyHandoverCommand                    *s50.HandoverCommand
	bodyHandoverRequestAcknowledge         *s49.HandoverRequestAcknowledge
	bodyPathSwitchRequestAcknowledge       *s58.PathSwitchRequestAcknowledge
	bodyHandoverCancelAcknowledge          *s29.HandoverCancelAcknowledge
	bodyERABSetupResponse                  *s57.ERABSetupResponse
	bodyERABModifyResponse                 *s57.ERABModifyResponse
	bodyERABReleaseResponse                *s57.ERABReleaseResponse
	bodyInitialContextSetupResponse        *s50.InitialContextSetupResponse
	bodyResetAcknowledge                   *s55.ResetAcknowledge
	bodyS1SetupResponse                    *s54.S1SetupResponse
	bodyUEContextModificationResponse      *s46.UEContextModificationResponse
	bodyUEContextReleaseComplete           *s57.UEContextReleaseComplete
	bodyENBConfigurationUpdateAcknowledge  *s28.ENBConfigurationUpdateAcknowledge
	bodyMMEConfigurationUpdateAcknowledge  *s30.MMEConfigurationUpdateAcknowledge
	bodyWriteReplaceWarningResponse        *WriteReplaceWarningResponse
	bodyKillResponse                       *s42.KillResponse
	bodyUERadioCapabilityMatchResponse     *s46.UERadioCapabilityMatchResponse
	bodyERABModificationConfirm            *s49.ERABModificationConfirm
	bodyUEContextModificationConfirm       *s45.UEContextModificationConfirm
	bodyUEContextSuspendResponse           *s46.UEContextSuspendResponse
	bodyUEContextResumeResponse            *s49.UEContextResumeResponse
	bodyUERadioCapabilityIDMappingResponse *s46.UERadioCapabilityIDMappingResponse
	bodyS1RemovalResponse                  *s31.S1RemovalResponse
}

// Opaque returns the retained opaque open value of SuccessfulValue and reports whether the opaque alternative is selected.
func (v *SuccessfulValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}

// AsHandoverCommand returns the selected HandoverCommand value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsHandoverCommand() (*s50.HandoverCommand, bool) {
	if v == nil || v.code != s00.ProcedureCode(0) || v.bodyHandoverCommand == nil {
		return nil, false
	}
	return v.bodyHandoverCommand, true
}

// AsHandoverRequestAcknowledge returns the selected HandoverRequestAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsHandoverRequestAcknowledge() (*s49.HandoverRequestAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(1) || v.bodyHandoverRequestAcknowledge == nil {
		return nil, false
	}
	return v.bodyHandoverRequestAcknowledge, true
}

// AsPathSwitchRequestAcknowledge returns the selected PathSwitchRequestAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsPathSwitchRequestAcknowledge() (*s58.PathSwitchRequestAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(3) || v.bodyPathSwitchRequestAcknowledge == nil {
		return nil, false
	}
	return v.bodyPathSwitchRequestAcknowledge, true
}

// AsHandoverCancelAcknowledge returns the selected HandoverCancelAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsHandoverCancelAcknowledge() (*s29.HandoverCancelAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(4) || v.bodyHandoverCancelAcknowledge == nil {
		return nil, false
	}
	return v.bodyHandoverCancelAcknowledge, true
}

// AsERABSetupResponse returns the selected ERABSetupResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsERABSetupResponse() (*s57.ERABSetupResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(5) || v.bodyERABSetupResponse == nil {
		return nil, false
	}
	return v.bodyERABSetupResponse, true
}

// AsERABModifyResponse returns the selected ERABModifyResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsERABModifyResponse() (*s57.ERABModifyResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(6) || v.bodyERABModifyResponse == nil {
		return nil, false
	}
	return v.bodyERABModifyResponse, true
}

// AsERABReleaseResponse returns the selected ERABReleaseResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsERABReleaseResponse() (*s57.ERABReleaseResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(7) || v.bodyERABReleaseResponse == nil {
		return nil, false
	}
	return v.bodyERABReleaseResponse, true
}

// AsInitialContextSetupResponse returns the selected InitialContextSetupResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsInitialContextSetupResponse() (*s50.InitialContextSetupResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(9) || v.bodyInitialContextSetupResponse == nil {
		return nil, false
	}
	return v.bodyInitialContextSetupResponse, true
}

// AsResetAcknowledge returns the selected ResetAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsResetAcknowledge() (*s55.ResetAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(14) || v.bodyResetAcknowledge == nil {
		return nil, false
	}
	return v.bodyResetAcknowledge, true
}

// AsS1SetupResponse returns the selected S1SetupResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsS1SetupResponse() (*s54.S1SetupResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(17) || v.bodyS1SetupResponse == nil {
		return nil, false
	}
	return v.bodyS1SetupResponse, true
}

// AsUEContextModificationResponse returns the selected UEContextModificationResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUEContextModificationResponse() (*s46.UEContextModificationResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(21) || v.bodyUEContextModificationResponse == nil {
		return nil, false
	}
	return v.bodyUEContextModificationResponse, true
}

// AsUEContextReleaseComplete returns the selected UEContextReleaseComplete value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUEContextReleaseComplete() (*s57.UEContextReleaseComplete, bool) {
	if v == nil || v.code != s00.ProcedureCode(23) || v.bodyUEContextReleaseComplete == nil {
		return nil, false
	}
	return v.bodyUEContextReleaseComplete, true
}

// AsENBConfigurationUpdateAcknowledge returns the selected ENBConfigurationUpdateAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsENBConfigurationUpdateAcknowledge() (*s28.ENBConfigurationUpdateAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(29) || v.bodyENBConfigurationUpdateAcknowledge == nil {
		return nil, false
	}
	return v.bodyENBConfigurationUpdateAcknowledge, true
}

// AsMMEConfigurationUpdateAcknowledge returns the selected MMEConfigurationUpdateAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsMMEConfigurationUpdateAcknowledge() (*s30.MMEConfigurationUpdateAcknowledge, bool) {
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
func (v *SuccessfulValue) AsKillResponse() (*s42.KillResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(43) || v.bodyKillResponse == nil {
		return nil, false
	}
	return v.bodyKillResponse, true
}

// AsUERadioCapabilityMatchResponse returns the selected UERadioCapabilityMatchResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUERadioCapabilityMatchResponse() (*s46.UERadioCapabilityMatchResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(48) || v.bodyUERadioCapabilityMatchResponse == nil {
		return nil, false
	}
	return v.bodyUERadioCapabilityMatchResponse, true
}

// AsERABModificationConfirm returns the selected ERABModificationConfirm value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsERABModificationConfirm() (*s49.ERABModificationConfirm, bool) {
	if v == nil || v.code != s00.ProcedureCode(50) || v.bodyERABModificationConfirm == nil {
		return nil, false
	}
	return v.bodyERABModificationConfirm, true
}

// AsUEContextModificationConfirm returns the selected UEContextModificationConfirm value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUEContextModificationConfirm() (*s45.UEContextModificationConfirm, bool) {
	if v == nil || v.code != s00.ProcedureCode(53) || v.bodyUEContextModificationConfirm == nil {
		return nil, false
	}
	return v.bodyUEContextModificationConfirm, true
}

// AsUEContextSuspendResponse returns the selected UEContextSuspendResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUEContextSuspendResponse() (*s46.UEContextSuspendResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(55) || v.bodyUEContextSuspendResponse == nil {
		return nil, false
	}
	return v.bodyUEContextSuspendResponse, true
}

// AsUEContextResumeResponse returns the selected UEContextResumeResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUEContextResumeResponse() (*s49.UEContextResumeResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(56) || v.bodyUEContextResumeResponse == nil {
		return nil, false
	}
	return v.bodyUEContextResumeResponse, true
}

// AsUERadioCapabilityIDMappingResponse returns the selected UERadioCapabilityIDMappingResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUERadioCapabilityIDMappingResponse() (*s46.UERadioCapabilityIDMappingResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(63) || v.bodyUERadioCapabilityIDMappingResponse == nil {
		return nil, false
	}
	return v.bodyUERadioCapabilityIDMappingResponse, true
}

// AsS1RemovalResponse returns the selected S1RemovalResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsS1RemovalResponse() (*s31.S1RemovalResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(67) || v.bodyS1RemovalResponse == nil {
		return nil, false
	}
	return v.bodyS1RemovalResponse, true
}
func BridgeDecodeSuccessfulValue(code s00.ProcedureCode, raw aper.OpaqueOpenType) (SuccessfulValue, error) {
	v := SuccessfulValue{code: code}
	switch code {
	case s00.ProcedureCode(0):
		var body s50.HandoverCommand
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s50.BridgeHandoverCommandMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.HandoverCommand:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverCommand")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s50.BridgeHandoverCommandFieldPerPadding(&body) = padding
		*s50.BridgeHandoverCommandFieldReceived(&body) = true
		raw.RetainContents(s50.BridgeHandoverCommandFieldReceivedBytes(&body))
		*s50.BridgeHandoverCommandFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyHandoverCommand = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(1):
		var body s49.HandoverRequestAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s49.BridgeHandoverRequestAcknowledgeMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.HandoverRequestAcknowledge:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverRequestAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s49.BridgeHandoverRequestAcknowledgeFieldPerPadding(&body) = padding
		*s49.BridgeHandoverRequestAcknowledgeFieldReceived(&body) = true
		raw.RetainContents(s49.BridgeHandoverRequestAcknowledgeFieldReceivedBytes(&body))
		*s49.BridgeHandoverRequestAcknowledgeFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyHandoverRequestAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(3):
		var body s58.PathSwitchRequestAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s58.BridgePathSwitchRequestAcknowledgeMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.PathSwitchRequestAcknowledge:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PathSwitchRequestAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s58.BridgePathSwitchRequestAcknowledgeFieldPerPadding(&body) = padding
		*s58.BridgePathSwitchRequestAcknowledgeFieldReceived(&body) = true
		raw.RetainContents(s58.BridgePathSwitchRequestAcknowledgeFieldReceivedBytes(&body))
		*s58.BridgePathSwitchRequestAcknowledgeFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyPathSwitchRequestAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(4):
		var body s29.HandoverCancelAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s29.BridgeHandoverCancelAcknowledgeMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.HandoverCancelAcknowledge:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverCancelAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s29.BridgeHandoverCancelAcknowledgeFieldPerPadding(&body) = padding
		*s29.BridgeHandoverCancelAcknowledgeFieldReceived(&body) = true
		raw.RetainContents(s29.BridgeHandoverCancelAcknowledgeFieldReceivedBytes(&body))
		*s29.BridgeHandoverCancelAcknowledgeFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyHandoverCancelAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(5):
		var body s57.ERABSetupResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s57.BridgeERABSetupResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ERABSetupResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABSetupResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s57.BridgeERABSetupResponseFieldPerPadding(&body) = padding
		*s57.BridgeERABSetupResponseFieldReceived(&body) = true
		raw.RetainContents(s57.BridgeERABSetupResponseFieldReceivedBytes(&body))
		*s57.BridgeERABSetupResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyERABSetupResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(6):
		var body s57.ERABModifyResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s57.BridgeERABModifyResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ERABModifyResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABModifyResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s57.BridgeERABModifyResponseFieldPerPadding(&body) = padding
		*s57.BridgeERABModifyResponseFieldReceived(&body) = true
		raw.RetainContents(s57.BridgeERABModifyResponseFieldReceivedBytes(&body))
		*s57.BridgeERABModifyResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyERABModifyResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(7):
		var body s57.ERABReleaseResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s57.BridgeERABReleaseResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ERABReleaseResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABReleaseResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s57.BridgeERABReleaseResponseFieldPerPadding(&body) = padding
		*s57.BridgeERABReleaseResponseFieldReceived(&body) = true
		raw.RetainContents(s57.BridgeERABReleaseResponseFieldReceivedBytes(&body))
		*s57.BridgeERABReleaseResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyERABReleaseResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(9):
		var body s50.InitialContextSetupResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s50.BridgeInitialContextSetupResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.InitialContextSetupResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "InitialContextSetupResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s50.BridgeInitialContextSetupResponseFieldPerPadding(&body) = padding
		*s50.BridgeInitialContextSetupResponseFieldReceived(&body) = true
		raw.RetainContents(s50.BridgeInitialContextSetupResponseFieldReceivedBytes(&body))
		*s50.BridgeInitialContextSetupResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyInitialContextSetupResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(14):
		var body s55.ResetAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s55.BridgeResetAcknowledgeMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ResetAcknowledge:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ResetAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s55.BridgeResetAcknowledgeFieldPerPadding(&body) = padding
		*s55.BridgeResetAcknowledgeFieldReceived(&body) = true
		raw.RetainContents(s55.BridgeResetAcknowledgeFieldReceivedBytes(&body))
		*s55.BridgeResetAcknowledgeFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyResetAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(17):
		var body s54.S1SetupResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s54.BridgeS1SetupResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.S1SetupResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "S1SetupResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s54.BridgeS1SetupResponseFieldPerPadding(&body) = padding
		*s54.BridgeS1SetupResponseFieldReceived(&body) = true
		raw.RetainContents(s54.BridgeS1SetupResponseFieldReceivedBytes(&body))
		*s54.BridgeS1SetupResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyS1SetupResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(21):
		var body s46.UEContextModificationResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s46.BridgeUEContextModificationResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UEContextModificationResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextModificationResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s46.BridgeUEContextModificationResponseFieldPerPadding(&body) = padding
		*s46.BridgeUEContextModificationResponseFieldReceived(&body) = true
		raw.RetainContents(s46.BridgeUEContextModificationResponseFieldReceivedBytes(&body))
		*s46.BridgeUEContextModificationResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextModificationResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(23):
		var body s57.UEContextReleaseComplete
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s57.BridgeUEContextReleaseCompleteMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UEContextReleaseComplete:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextReleaseComplete")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s57.BridgeUEContextReleaseCompleteFieldPerPadding(&body) = padding
		*s57.BridgeUEContextReleaseCompleteFieldReceived(&body) = true
		raw.RetainContents(s57.BridgeUEContextReleaseCompleteFieldReceivedBytes(&body))
		*s57.BridgeUEContextReleaseCompleteFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextReleaseComplete = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(29):
		var body s28.ENBConfigurationUpdateAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s28.BridgeENBConfigurationUpdateAcknowledgeMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ENBConfigurationUpdateAcknowledge:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBConfigurationUpdateAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s28.BridgeENBConfigurationUpdateAcknowledgeFieldPerPadding(&body) = padding
		*s28.BridgeENBConfigurationUpdateAcknowledgeFieldReceived(&body) = true
		raw.RetainContents(s28.BridgeENBConfigurationUpdateAcknowledgeFieldReceivedBytes(&body))
		*s28.BridgeENBConfigurationUpdateAcknowledgeFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyENBConfigurationUpdateAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(30):
		var body s30.MMEConfigurationUpdateAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s30.BridgeMMEConfigurationUpdateAcknowledgeMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.MMEConfigurationUpdateAcknowledge:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "MMEConfigurationUpdateAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s30.BridgeMMEConfigurationUpdateAcknowledgeFieldPerPadding(&body) = padding
		*s30.BridgeMMEConfigurationUpdateAcknowledgeFieldReceived(&body) = true
		raw.RetainContents(s30.BridgeMMEConfigurationUpdateAcknowledgeFieldReceivedBytes(&body))
		*s30.BridgeMMEConfigurationUpdateAcknowledgeFieldReceivedLocation(&body) = raw.ContentLocation()
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
		var body s42.KillResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s42.BridgeKillResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.KillResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "KillResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s42.BridgeKillResponseFieldPerPadding(&body) = padding
		*s42.BridgeKillResponseFieldReceived(&body) = true
		raw.RetainContents(s42.BridgeKillResponseFieldReceivedBytes(&body))
		*s42.BridgeKillResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyKillResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(48):
		var body s46.UERadioCapabilityMatchResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s46.BridgeUERadioCapabilityMatchResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UERadioCapabilityMatchResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UERadioCapabilityMatchResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s46.BridgeUERadioCapabilityMatchResponseFieldPerPadding(&body) = padding
		*s46.BridgeUERadioCapabilityMatchResponseFieldReceived(&body) = true
		raw.RetainContents(s46.BridgeUERadioCapabilityMatchResponseFieldReceivedBytes(&body))
		*s46.BridgeUERadioCapabilityMatchResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUERadioCapabilityMatchResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(50):
		var body s49.ERABModificationConfirm
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s49.BridgeERABModificationConfirmMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ERABModificationConfirm:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ERABModificationConfirm")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s49.BridgeERABModificationConfirmFieldPerPadding(&body) = padding
		*s49.BridgeERABModificationConfirmFieldReceived(&body) = true
		raw.RetainContents(s49.BridgeERABModificationConfirmFieldReceivedBytes(&body))
		*s49.BridgeERABModificationConfirmFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyERABModificationConfirm = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(53):
		var body s45.UEContextModificationConfirm
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s45.BridgeUEContextModificationConfirmMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UEContextModificationConfirm:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextModificationConfirm")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s45.BridgeUEContextModificationConfirmFieldPerPadding(&body) = padding
		*s45.BridgeUEContextModificationConfirmFieldReceived(&body) = true
		raw.RetainContents(s45.BridgeUEContextModificationConfirmFieldReceivedBytes(&body))
		*s45.BridgeUEContextModificationConfirmFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextModificationConfirm = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(55):
		var body s46.UEContextSuspendResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s46.BridgeUEContextSuspendResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UEContextSuspendResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextSuspendResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s46.BridgeUEContextSuspendResponseFieldPerPadding(&body) = padding
		*s46.BridgeUEContextSuspendResponseFieldReceived(&body) = true
		raw.RetainContents(s46.BridgeUEContextSuspendResponseFieldReceivedBytes(&body))
		*s46.BridgeUEContextSuspendResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextSuspendResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(56):
		var body s49.UEContextResumeResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s49.BridgeUEContextResumeResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UEContextResumeResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextResumeResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s49.BridgeUEContextResumeResponseFieldPerPadding(&body) = padding
		*s49.BridgeUEContextResumeResponseFieldReceived(&body) = true
		raw.RetainContents(s49.BridgeUEContextResumeResponseFieldReceivedBytes(&body))
		*s49.BridgeUEContextResumeResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextResumeResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(63):
		var body s46.UERadioCapabilityIDMappingResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s46.BridgeUERadioCapabilityIDMappingResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UERadioCapabilityIDMappingResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UERadioCapabilityIDMappingResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s46.BridgeUERadioCapabilityIDMappingResponseFieldPerPadding(&body) = padding
		*s46.BridgeUERadioCapabilityIDMappingResponseFieldReceived(&body) = true
		raw.RetainContents(s46.BridgeUERadioCapabilityIDMappingResponseFieldReceivedBytes(&body))
		*s46.BridgeUERadioCapabilityIDMappingResponseFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUERadioCapabilityIDMappingResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(67):
		var body s31.S1RemovalResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s31.BridgeS1RemovalResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.S1RemovalResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "S1RemovalResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s31.BridgeS1RemovalResponseFieldPerPadding(&body) = padding
		*s31.BridgeS1RemovalResponseFieldReceived(&body) = true
		raw.RetainContents(s31.BridgeS1RemovalResponseFieldReceivedBytes(&body))
		*s31.BridgeS1RemovalResponseFieldReceivedLocation(&body) = raw.ContentLocation()
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
		return s50.BridgeHandoverCommandMethodMarshalAPERBudget(v.bodyHandoverCommand, budget, fresh)
	case s00.ProcedureCode(1):
		if v.bodyHandoverRequestAcknowledge == nil {
			return nil, fmt.Errorf("%s value: missing HandoverRequestAcknowledge", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s49.BridgeHandoverRequestAcknowledgeMethodMarshalAPERBudget(v.bodyHandoverRequestAcknowledge, budget, fresh)
	case s00.ProcedureCode(3):
		if v.bodyPathSwitchRequestAcknowledge == nil {
			return nil, fmt.Errorf("%s value: missing PathSwitchRequestAcknowledge", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s58.BridgePathSwitchRequestAcknowledgeMethodMarshalAPERBudget(v.bodyPathSwitchRequestAcknowledge, budget, fresh)
	case s00.ProcedureCode(4):
		if v.bodyHandoverCancelAcknowledge == nil {
			return nil, fmt.Errorf("%s value: missing HandoverCancelAcknowledge", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s29.BridgeHandoverCancelAcknowledgeMethodMarshalAPERBudget(v.bodyHandoverCancelAcknowledge, budget, fresh)
	case s00.ProcedureCode(5):
		if v.bodyERABSetupResponse == nil {
			return nil, fmt.Errorf("%s value: missing ERABSetupResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s57.BridgeERABSetupResponseMethodMarshalAPERBudget(v.bodyERABSetupResponse, budget, fresh)
	case s00.ProcedureCode(6):
		if v.bodyERABModifyResponse == nil {
			return nil, fmt.Errorf("%s value: missing ERABModifyResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s57.BridgeERABModifyResponseMethodMarshalAPERBudget(v.bodyERABModifyResponse, budget, fresh)
	case s00.ProcedureCode(7):
		if v.bodyERABReleaseResponse == nil {
			return nil, fmt.Errorf("%s value: missing ERABReleaseResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s57.BridgeERABReleaseResponseMethodMarshalAPERBudget(v.bodyERABReleaseResponse, budget, fresh)
	case s00.ProcedureCode(9):
		if v.bodyInitialContextSetupResponse == nil {
			return nil, fmt.Errorf("%s value: missing InitialContextSetupResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s50.BridgeInitialContextSetupResponseMethodMarshalAPERBudget(v.bodyInitialContextSetupResponse, budget, fresh)
	case s00.ProcedureCode(14):
		if v.bodyResetAcknowledge == nil {
			return nil, fmt.Errorf("%s value: missing ResetAcknowledge", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s55.BridgeResetAcknowledgeMethodMarshalAPERBudget(v.bodyResetAcknowledge, budget, fresh)
	case s00.ProcedureCode(17):
		if v.bodyS1SetupResponse == nil {
			return nil, fmt.Errorf("%s value: missing S1SetupResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s54.BridgeS1SetupResponseMethodMarshalAPERBudget(v.bodyS1SetupResponse, budget, fresh)
	case s00.ProcedureCode(21):
		if v.bodyUEContextModificationResponse == nil {
			return nil, fmt.Errorf("%s value: missing UEContextModificationResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s46.BridgeUEContextModificationResponseMethodMarshalAPERBudget(v.bodyUEContextModificationResponse, budget, fresh)
	case s00.ProcedureCode(23):
		if v.bodyUEContextReleaseComplete == nil {
			return nil, fmt.Errorf("%s value: missing UEContextReleaseComplete", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s57.BridgeUEContextReleaseCompleteMethodMarshalAPERBudget(v.bodyUEContextReleaseComplete, budget, fresh)
	case s00.ProcedureCode(29):
		if v.bodyENBConfigurationUpdateAcknowledge == nil {
			return nil, fmt.Errorf("%s value: missing ENBConfigurationUpdateAcknowledge", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s28.BridgeENBConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(v.bodyENBConfigurationUpdateAcknowledge, budget, fresh)
	case s00.ProcedureCode(30):
		if v.bodyMMEConfigurationUpdateAcknowledge == nil {
			return nil, fmt.Errorf("%s value: missing MMEConfigurationUpdateAcknowledge", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s30.BridgeMMEConfigurationUpdateAcknowledgeMethodMarshalAPERBudget(v.bodyMMEConfigurationUpdateAcknowledge, budget, fresh)
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
		return s42.BridgeKillResponseMethodMarshalAPERBudget(v.bodyKillResponse, budget, fresh)
	case s00.ProcedureCode(48):
		if v.bodyUERadioCapabilityMatchResponse == nil {
			return nil, fmt.Errorf("%s value: missing UERadioCapabilityMatchResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s46.BridgeUERadioCapabilityMatchResponseMethodMarshalAPERBudget(v.bodyUERadioCapabilityMatchResponse, budget, fresh)
	case s00.ProcedureCode(50):
		if v.bodyERABModificationConfirm == nil {
			return nil, fmt.Errorf("%s value: missing ERABModificationConfirm", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s49.BridgeERABModificationConfirmMethodMarshalAPERBudget(v.bodyERABModificationConfirm, budget, fresh)
	case s00.ProcedureCode(53):
		if v.bodyUEContextModificationConfirm == nil {
			return nil, fmt.Errorf("%s value: missing UEContextModificationConfirm", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s45.BridgeUEContextModificationConfirmMethodMarshalAPERBudget(v.bodyUEContextModificationConfirm, budget, fresh)
	case s00.ProcedureCode(55):
		if v.bodyUEContextSuspendResponse == nil {
			return nil, fmt.Errorf("%s value: missing UEContextSuspendResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s46.BridgeUEContextSuspendResponseMethodMarshalAPERBudget(v.bodyUEContextSuspendResponse, budget, fresh)
	case s00.ProcedureCode(56):
		if v.bodyUEContextResumeResponse == nil {
			return nil, fmt.Errorf("%s value: missing UEContextResumeResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s49.BridgeUEContextResumeResponseMethodMarshalAPERBudget(v.bodyUEContextResumeResponse, budget, fresh)
	case s00.ProcedureCode(63):
		if v.bodyUERadioCapabilityIDMappingResponse == nil {
			return nil, fmt.Errorf("%s value: missing UERadioCapabilityIDMappingResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s46.BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERBudget(v.bodyUERadioCapabilityIDMappingResponse, budget, fresh)
	case s00.ProcedureCode(67):
		if v.bodyS1RemovalResponse == nil {
			return nil, fmt.Errorf("%s value: missing S1RemovalResponse", "Successful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s31.BridgeS1RemovalResponseMethodMarshalAPERBudget(v.bodyS1RemovalResponse, budget, fresh)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
	s40.BridgeCaptureS1APENDCSONTransferType(&v.Transfertype, s)
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
	s15.BridgeENDCSONConfigurationTransferExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APENDCSONConfigurationTransfer(v *ENDCSONConfigurationTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s40.BridgeCompareS1APENDCSONTransferType(&v.Transfertype, s)
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
	s15.BridgeENDCSONConfigurationTransferExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APMMEConfigurationTransferIEValue(v *MMEConfigurationTransferIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(130):
			{
				f := s.Begin()
				s.Bool(v.rowSONConfigurationTransferMCT == nil)
				if v.rowSONConfigurationTransferMCT != nil {
					BridgeCaptureS1APSONConfigurationTransfer(v.rowSONConfigurationTransferMCT, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(295):
			{
				f := s.Begin()
				s.Bool(v.rowENDCSONConfigurationTransferMCT == nil)
				if v.rowENDCSONConfigurationTransferMCT != nil {
					BridgeCaptureS1APENDCSONConfigurationTransfer(v.rowENDCSONConfigurationTransferMCT, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(309):
			{
				f := s.Begin()
				s.Bool(v.rowIntersystemSONConfigurationTransferMCT == nil)
				if v.rowIntersystemSONConfigurationTransferMCT != nil {
					s00.BridgeCaptureS1APIntersystemSONConfigurationTransfer(v.rowIntersystemSONConfigurationTransferMCT, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEConfigurationTransferIEValue) captureSemantics(s aper.SemanticCapture) MMEConfigurationTransferIEValue {
	BridgeCaptureS1APMMEConfigurationTransferIEValue(&v, &s)
	return v
}
func BridgeCompareS1APMMEConfigurationTransferIEValue(v *MMEConfigurationTransferIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(130):
			{
				f := s.Begin()
				s.Bool(v.rowSONConfigurationTransferMCT == nil)
				if v.rowSONConfigurationTransferMCT != nil {
					BridgeCompareS1APSONConfigurationTransfer(v.rowSONConfigurationTransferMCT, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(295):
			{
				f := s.Begin()
				s.Bool(v.rowENDCSONConfigurationTransferMCT == nil)
				if v.rowENDCSONConfigurationTransferMCT != nil {
					BridgeCompareS1APENDCSONConfigurationTransfer(v.rowENDCSONConfigurationTransferMCT, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(309):
			{
				f := s.Begin()
				s.Bool(v.rowIntersystemSONConfigurationTransferMCT == nil)
				if v.rowIntersystemSONConfigurationTransferMCT != nil {
					s02.BridgeCompareS1APIntersystemSONConfigurationTransfer(v.rowIntersystemSONConfigurationTransferMCT, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v MMEConfigurationTransferIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APMMEConfigurationTransferIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APSONConfigurationTransfer(v *SONConfigurationTransfer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s43.BridgeCaptureS1APTargeteNBID(&v.TargeteNBID, s)
	s41.BridgeCaptureS1APSourceeNBID(&v.SourceeNBID, s)
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
	s43.BridgeCompareS1APTargeteNBID(&v.TargeteNBID, s)
	s41.BridgeCompareS1APSourceeNBID(&v.SourceeNBID, s)
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
					s40.BridgeCaptureS1APSynchronisationInformation(v.rowSynchronisationInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(356):
			{
				f := s.Begin()
				s.Bool(v.rowRequestedTNLInfo == nil)
				if v.rowRequestedTNLInfo != nil {
					s31.BridgeCaptureS1APRequestedTNLInfo(v.rowRequestedTNLInfo, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s40.BridgeCompareS1APSynchronisationInformation(v.rowSynchronisationInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(356):
			{
				f := s.Begin()
				s.Bool(v.rowRequestedTNLInfo == nil)
				if v.rowRequestedTNLInfo != nil {
					s31.BridgeCompareS1APRequestedTNLInfo(v.rowRequestedTNLInfo, s)
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
				s24.BridgeCaptureS1APSONInformationExtension(v.SONInformationExtension, s)
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
				s08.BridgeCompareS1APSONInformationRequest(v.SONInformationRequest, s)
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
				s24.BridgeCompareS1APSONInformationExtension(v.SONInformationExtension, s)
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
	s44.BridgeSONInformationReplyExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s44.BridgeSONInformationReplyExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
	s03.BridgeCompareS1APProcedureCode(&v.ProcedureCode, s)
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
					s50.BridgeCaptureS1APHandoverCommand(v.bodyHandoverCommand, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(1):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverRequestAcknowledge == nil)
				if v.bodyHandoverRequestAcknowledge != nil {
					s49.BridgeCaptureS1APHandoverRequestAcknowledge(v.bodyHandoverRequestAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(3):
			{
				f := s.Begin()
				s.Bool(v.bodyPathSwitchRequestAcknowledge == nil)
				if v.bodyPathSwitchRequestAcknowledge != nil {
					s58.BridgeCaptureS1APPathSwitchRequestAcknowledge(v.bodyPathSwitchRequestAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(4):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverCancelAcknowledge == nil)
				if v.bodyHandoverCancelAcknowledge != nil {
					s29.BridgeCaptureS1APHandoverCancelAcknowledge(v.bodyHandoverCancelAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(5):
			{
				f := s.Begin()
				s.Bool(v.bodyERABSetupResponse == nil)
				if v.bodyERABSetupResponse != nil {
					s57.BridgeCaptureS1APERABSetupResponse(v.bodyERABSetupResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyERABModifyResponse == nil)
				if v.bodyERABModifyResponse != nil {
					s57.BridgeCaptureS1APERABModifyResponse(v.bodyERABModifyResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyERABReleaseResponse == nil)
				if v.bodyERABReleaseResponse != nil {
					s57.BridgeCaptureS1APERABReleaseResponse(v.bodyERABReleaseResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyInitialContextSetupResponse == nil)
				if v.bodyInitialContextSetupResponse != nil {
					s50.BridgeCaptureS1APInitialContextSetupResponse(v.bodyInitialContextSetupResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(14):
			{
				f := s.Begin()
				s.Bool(v.bodyResetAcknowledge == nil)
				if v.bodyResetAcknowledge != nil {
					s55.BridgeCaptureS1APResetAcknowledge(v.bodyResetAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(17):
			{
				f := s.Begin()
				s.Bool(v.bodyS1SetupResponse == nil)
				if v.bodyS1SetupResponse != nil {
					s54.BridgeCaptureS1APS1SetupResponse(v.bodyS1SetupResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationResponse == nil)
				if v.bodyUEContextModificationResponse != nil {
					s46.BridgeCaptureS1APUEContextModificationResponse(v.bodyUEContextModificationResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(23):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextReleaseComplete == nil)
				if v.bodyUEContextReleaseComplete != nil {
					s57.BridgeCaptureS1APUEContextReleaseComplete(v.bodyUEContextReleaseComplete, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(29):
			{
				f := s.Begin()
				s.Bool(v.bodyENBConfigurationUpdateAcknowledge == nil)
				if v.bodyENBConfigurationUpdateAcknowledge != nil {
					s28.BridgeCaptureS1APENBConfigurationUpdateAcknowledge(v.bodyENBConfigurationUpdateAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(30):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEConfigurationUpdateAcknowledge == nil)
				if v.bodyMMEConfigurationUpdateAcknowledge != nil {
					s30.BridgeCaptureS1APMMEConfigurationUpdateAcknowledge(v.bodyMMEConfigurationUpdateAcknowledge, s)
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
					s42.BridgeCaptureS1APKillResponse(v.bodyKillResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(48):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityMatchResponse == nil)
				if v.bodyUERadioCapabilityMatchResponse != nil {
					s46.BridgeCaptureS1APUERadioCapabilityMatchResponse(v.bodyUERadioCapabilityMatchResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(50):
			{
				f := s.Begin()
				s.Bool(v.bodyERABModificationConfirm == nil)
				if v.bodyERABModificationConfirm != nil {
					s49.BridgeCaptureS1APERABModificationConfirm(v.bodyERABModificationConfirm, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(53):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationConfirm == nil)
				if v.bodyUEContextModificationConfirm != nil {
					s45.BridgeCaptureS1APUEContextModificationConfirm(v.bodyUEContextModificationConfirm, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(55):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextSuspendResponse == nil)
				if v.bodyUEContextSuspendResponse != nil {
					s46.BridgeCaptureS1APUEContextSuspendResponse(v.bodyUEContextSuspendResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(56):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextResumeResponse == nil)
				if v.bodyUEContextResumeResponse != nil {
					s49.BridgeCaptureS1APUEContextResumeResponse(v.bodyUEContextResumeResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(63):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityIDMappingResponse == nil)
				if v.bodyUERadioCapabilityIDMappingResponse != nil {
					s46.BridgeCaptureS1APUERadioCapabilityIDMappingResponse(v.bodyUERadioCapabilityIDMappingResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(67):
			{
				f := s.Begin()
				s.Bool(v.bodyS1RemovalResponse == nil)
				if v.bodyS1RemovalResponse != nil {
					s31.BridgeCaptureS1APS1RemovalResponse(v.bodyS1RemovalResponse, s)
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
	s03.BridgeCompareS1APProcedureCode(&v.code, s)
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
					s50.BridgeCompareS1APHandoverCommand(v.bodyHandoverCommand, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(1):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverRequestAcknowledge == nil)
				if v.bodyHandoverRequestAcknowledge != nil {
					s49.BridgeCompareS1APHandoverRequestAcknowledge(v.bodyHandoverRequestAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(3):
			{
				f := s.Begin()
				s.Bool(v.bodyPathSwitchRequestAcknowledge == nil)
				if v.bodyPathSwitchRequestAcknowledge != nil {
					s58.BridgeCompareS1APPathSwitchRequestAcknowledge(v.bodyPathSwitchRequestAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(4):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverCancelAcknowledge == nil)
				if v.bodyHandoverCancelAcknowledge != nil {
					s29.BridgeCompareS1APHandoverCancelAcknowledge(v.bodyHandoverCancelAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(5):
			{
				f := s.Begin()
				s.Bool(v.bodyERABSetupResponse == nil)
				if v.bodyERABSetupResponse != nil {
					s57.BridgeCompareS1APERABSetupResponse(v.bodyERABSetupResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyERABModifyResponse == nil)
				if v.bodyERABModifyResponse != nil {
					s57.BridgeCompareS1APERABModifyResponse(v.bodyERABModifyResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyERABReleaseResponse == nil)
				if v.bodyERABReleaseResponse != nil {
					s57.BridgeCompareS1APERABReleaseResponse(v.bodyERABReleaseResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyInitialContextSetupResponse == nil)
				if v.bodyInitialContextSetupResponse != nil {
					s50.BridgeCompareS1APInitialContextSetupResponse(v.bodyInitialContextSetupResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(14):
			{
				f := s.Begin()
				s.Bool(v.bodyResetAcknowledge == nil)
				if v.bodyResetAcknowledge != nil {
					s55.BridgeCompareS1APResetAcknowledge(v.bodyResetAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(17):
			{
				f := s.Begin()
				s.Bool(v.bodyS1SetupResponse == nil)
				if v.bodyS1SetupResponse != nil {
					s54.BridgeCompareS1APS1SetupResponse(v.bodyS1SetupResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationResponse == nil)
				if v.bodyUEContextModificationResponse != nil {
					s46.BridgeCompareS1APUEContextModificationResponse(v.bodyUEContextModificationResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(23):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextReleaseComplete == nil)
				if v.bodyUEContextReleaseComplete != nil {
					s57.BridgeCompareS1APUEContextReleaseComplete(v.bodyUEContextReleaseComplete, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(29):
			{
				f := s.Begin()
				s.Bool(v.bodyENBConfigurationUpdateAcknowledge == nil)
				if v.bodyENBConfigurationUpdateAcknowledge != nil {
					s28.BridgeCompareS1APENBConfigurationUpdateAcknowledge(v.bodyENBConfigurationUpdateAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(30):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEConfigurationUpdateAcknowledge == nil)
				if v.bodyMMEConfigurationUpdateAcknowledge != nil {
					s30.BridgeCompareS1APMMEConfigurationUpdateAcknowledge(v.bodyMMEConfigurationUpdateAcknowledge, s)
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
					s42.BridgeCompareS1APKillResponse(v.bodyKillResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(48):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityMatchResponse == nil)
				if v.bodyUERadioCapabilityMatchResponse != nil {
					s46.BridgeCompareS1APUERadioCapabilityMatchResponse(v.bodyUERadioCapabilityMatchResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(50):
			{
				f := s.Begin()
				s.Bool(v.bodyERABModificationConfirm == nil)
				if v.bodyERABModificationConfirm != nil {
					s49.BridgeCompareS1APERABModificationConfirm(v.bodyERABModificationConfirm, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(53):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationConfirm == nil)
				if v.bodyUEContextModificationConfirm != nil {
					s45.BridgeCompareS1APUEContextModificationConfirm(v.bodyUEContextModificationConfirm, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(55):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextSuspendResponse == nil)
				if v.bodyUEContextSuspendResponse != nil {
					s46.BridgeCompareS1APUEContextSuspendResponse(v.bodyUEContextSuspendResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(56):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextResumeResponse == nil)
				if v.bodyUEContextResumeResponse != nil {
					s49.BridgeCompareS1APUEContextResumeResponse(v.bodyUEContextResumeResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(63):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityIDMappingResponse == nil)
				if v.bodyUERadioCapabilityIDMappingResponse != nil {
					s46.BridgeCompareS1APUERadioCapabilityIDMappingResponse(v.bodyUERadioCapabilityIDMappingResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(67):
			{
				f := s.Begin()
				s.Bool(v.bodyS1RemovalResponse == nil)
				if v.bodyS1RemovalResponse != nil {
					s31.BridgeCompareS1APS1RemovalResponse(v.bodyS1RemovalResponse, s)
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
	s08.BridgeCompareS1APENBX2TLAs(&v.ENBX2TransportLayerAddresses, s)
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
	Transfertype      s40.ENDCSONTransferType                            `asn1:"tag:0,context,explicit"`
	SONInformation    SONInformation                                     `asn1:"tag:1,context,explicit"`
	X2TNLConfigInfo   *X2TNLConfigurationInfo                            `asn1:"tag:2,context,implicit,optional" json:"X2TNLConfigInfo,omitempty"`
	IEExtensions      s09.ENDCSONConfigurationTransferExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	SONInformationExtension *s24.SONInformationExtension `json:"SONInformationExtension,omitempty"`
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
func BridgeNewSONInformationSONInformationExtensionLegacy(v s24.SONInformationExtension) SONInformation {
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
	IEExtensions           s44.SONInformationReplyExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	TargeteNBID       s43.TargeteNBID                            `asn1:"tag:0,context,implicit"`
	SourceeNBID       s41.SourceeNBID                            `asn1:"tag:1,context,implicit"`
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
	IEExtensions                      s48.X2TNLConfigurationInfoExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
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
	if err := aper.EncodeBoolean(bb, v.X2TNLConfigInfo != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := s40.BridgeENDCSONTransferTypeMethodMarshalAPERTo(&v.Transfertype, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
				if err := s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ENDCSONConfigurationTransfer from APER format.
func (v *ENDCSONConfigurationTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *ENDCSONConfigurationTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCSONConfigurationTransfer{}
	var extAdditions aper.ExtensionAdditions
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
	if err := s40.BridgeENDCSONTransferTypeMethodUnmarshalAPERFrom(&v.Transfertype, bb); err != nil {
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
		tmp_ieextensions := make(s09.ENDCSONConfigurationTransferExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s09.ENDCSONConfigurationTransferExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s09.BridgeENDCSONConfigurationTransferExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s24.BridgeSONInformationExtensionMethodMarshalAPERTo(v.SONInformationExtension, inner, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding sONInformation-Extension: %w", err)
			}
		default:
			return fmt.Errorf("unknown SONInformation extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(s08.BridgeFreshCompletePadding(v.perOpenTypePadding, fresh...))
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
			var dec_soninformationextension s24.SONInformationExtension
			if err := s24.BridgeSONInformationExtensionMethodUnmarshalAPERFrom(&dec_soninformationextension, inner); err != nil {
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
				if err := s44.BridgeSONInformationReplyExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SONInformationReply from APER format.
func (v *SONInformationReply) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *SONInformationReply) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONInformationReply{}
	var extAdditions aper.ExtensionAdditions
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
		tmp_ieextensions := make(s44.SONInformationReplyExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s44.SONInformationReplyExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s44.BridgeSONInformationReplyExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
	if err := s43.BridgeTargeteNBIDMethodMarshalAPERTo(&v.TargeteNBID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding targeteNB-ID: %w", err)
	}
	if err := s41.BridgeSourceeNBIDMethodMarshalAPERTo(&v.SourceeNBID, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SONConfigurationTransfer from APER format.
func (v *SONConfigurationTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *SONConfigurationTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SONConfigurationTransfer{}
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
	toleranceMark_targetenbid := bb.EnterComponent("TargeteNBID")
	if err := s43.BridgeTargeteNBIDMethodUnmarshalAPERFrom(&v.TargeteNBID, bb); err != nil {
		return runtime.WrapDecodePath(err, "TargeteNBID")
	}
	bb.LeaveComponent(toleranceMark_targetenbid)
	toleranceMark_sourceenbid := bb.EnterComponent("SourceeNBID")
	if err := s41.BridgeSourceeNBIDMethodUnmarshalAPERFrom(&v.SourceeNBID, bb); err != nil {
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
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
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
				if err := s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes X2TNLConfigurationInfo from APER format.
func (v *X2TNLConfigurationInfo) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *X2TNLConfigurationInfo) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = X2TNLConfigurationInfo{}
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
	toleranceMark_enbx2transportlayeraddresses := bb.EnterComponent("ENBX2TransportLayerAddresses")
	v.ENBX2TransportLayerAddresses = make(s00.ENBX2TLAs, 0)
	_, errCollection_enbx2transportlayeraddresses := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 2, HasUpper: true}, true, func(fragmentOffset_enbx2transportlayeraddresses, fragmentLength_enbx2transportlayeraddresses int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_6: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1201
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
		tmp_ieextensions := make(s48.X2TNLConfigurationInfoExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s48.X2TNLConfigurationInfoExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s48.BridgeX2TNLConfigurationInfoExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ENDCSONConfigurationTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "ENDCSONConfigurationTransfer", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONConfigurationTransfer", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONInformation", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SONInformationReply", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "X2TNLConfigurationInfo", v.receivedLocation, v.perPadding)
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
func NewSONInformationSONInformationExtension(v s24.SONInformationExtension, options ...aper.BuildOption) (SONInformation, error) {
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
	ProtocolIEs      s42.WriteReplaceWarningRequestIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s41.WriteReplaceWarningResponseIEContainer `asn1:"tag:0,context,implicit"`
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
			if err := s42.BridgeWriteReplaceWarningRequestIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes WriteReplaceWarningRequest from APER format.
func (v *WriteReplaceWarningRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *WriteReplaceWarningRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WriteReplaceWarningRequest{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s42.WriteReplaceWarningRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s42.WriteReplaceWarningRequestIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s42.BridgeWriteReplaceWarningRequestIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s41.BridgeWriteReplaceWarningResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes WriteReplaceWarningResponse from APER format.
func (v *WriteReplaceWarningResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *WriteReplaceWarningResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WriteReplaceWarningResponse{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s41.WriteReplaceWarningResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s41.WriteReplaceWarningResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s41.BridgeWriteReplaceWarningResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *WriteReplaceWarningRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "WriteReplaceWarningRequest", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "WriteReplaceWarningResponse", v.receivedLocation, v.perPadding)
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.ProcedureCode), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false); err != nil {
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
	val_procedurecode, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(255), false)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "SuccessfulOutcome", v.receivedLocation, v.perPadding)
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
	rowSynchronisationInformation *s40.SynchronisationInformation
	rowRequestedTNLInfo           *s31.RequestedTNLInfo
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
func (v *SONConfigurationTransferExtIEsValue) AsSynchronisationInformation() (*s40.SynchronisationInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(209) || v.rowSynchronisationInformation == nil {
		return nil, false
	}
	return v.rowSynchronisationInformation, true
}

// AsRequestedTNLInfo returns the selected RequestedTNLInfo value of SONConfigurationTransferExtIEsValue and reports whether that alternative is active.
func (v *SONConfigurationTransferExtIEsValue) AsRequestedTNLInfo() (*s31.RequestedTNLInfo, bool) {
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
		var value s40.SynchronisationInformation
		child := scope
		if err := s40.BridgeSynchronisationInformationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SynchronisationInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SynchronisationInformation")
		if err != nil {
			return out, err
		}
		*s40.BridgeSynchronisationInformationFieldPerPadding(&value) = padding
		*s40.BridgeSynchronisationInformationFieldReceived(&value) = true
		raw.RetainContents(s40.BridgeSynchronisationInformationFieldReceivedBytes(&value))
		*s40.BridgeSynchronisationInformationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSynchronisationInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(356):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s31.RequestedTNLInfo
		child := scope
		if err := s31.BridgeRequestedTNLInfoMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "RequestedTNLInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "RequestedTNLInfo")
		if err != nil {
			return out, err
		}
		*s31.BridgeRequestedTNLInfoFieldPerPadding(&value) = padding
		*s31.BridgeRequestedTNLInfoFieldReceived(&value) = true
		raw.RetainContents(s31.BridgeRequestedTNLInfoFieldReceivedBytes(&value))
		*s31.BridgeRequestedTNLInfoFieldReceivedLocation(&value) = raw.ContentLocation()
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
		candidate, err := s40.BridgeSynchronisationInformationMethodMarshalAPERBudget(v.rowSynchronisationInformation, budget, fresh)
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
		candidate, err := s31.BridgeRequestedTNLInfoMethodMarshalAPERBudget(v.rowRequestedTNLInfo, budget, fresh)
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

type MMEConfigurationTransferIEValue struct {
	id                                        s00.ProtocolIEID
	received                                  aper.WireSpan
	replay                                    aper.Snapshot
	opaque                                    aper.OpaqueOpenType
	isOpaque                                  bool
	rowSONConfigurationTransferMCT            *SONConfigurationTransfer
	rowENDCSONConfigurationTransferMCT        *ENDCSONConfigurationTransfer
	rowIntersystemSONConfigurationTransferMCT *s00.IntersystemSONConfigurationTransfer
}

func (v MMEConfigurationTransferIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(130):
		return v.rowSONConfigurationTransferMCT != nil
	case s00.ProtocolIEID(295):
		return v.rowENDCSONConfigurationTransferMCT != nil
	case s00.ProtocolIEID(309):
		return v.rowIntersystemSONConfigurationTransferMCT != nil
	}
	return false
}

// Opaque returns the retained opaque open value of MMEConfigurationTransferIEValue and reports whether the opaque alternative is selected.
func (v *MMEConfigurationTransferIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (MMEConfigurationTransferIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "MMEConfigurationTransferIEs"}}
}
func (MMEConfigurationTransferIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(130):
		return aper.UnknownSelector
	case s00.ProtocolIEID(295):
		return aper.UnknownSelector
	case s00.ProtocolIEID(309):
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
	case s00.ProtocolIEID(294):
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
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsSONConfigurationTransferMCT returns the selected SONConfigurationTransferMCT value of MMEConfigurationTransferIEValue and reports whether that alternative is active.
func (v *MMEConfigurationTransferIEValue) AsSONConfigurationTransferMCT() (*SONConfigurationTransfer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(130) || v.rowSONConfigurationTransferMCT == nil {
		return nil, false
	}
	return v.rowSONConfigurationTransferMCT, true
}

// AsENDCSONConfigurationTransferMCT returns the selected ENDCSONConfigurationTransferMCT value of MMEConfigurationTransferIEValue and reports whether that alternative is active.
func (v *MMEConfigurationTransferIEValue) AsENDCSONConfigurationTransferMCT() (*ENDCSONConfigurationTransfer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(295) || v.rowENDCSONConfigurationTransferMCT == nil {
		return nil, false
	}
	return v.rowENDCSONConfigurationTransferMCT, true
}

// AsIntersystemSONConfigurationTransferMCT returns the selected IntersystemSONConfigurationTransferMCT value of MMEConfigurationTransferIEValue and reports whether that alternative is active.
func (v *MMEConfigurationTransferIEValue) AsIntersystemSONConfigurationTransferMCT() (*s00.IntersystemSONConfigurationTransfer, bool) {
	if v == nil || v.id != s00.ProtocolIEID(309) || v.rowIntersystemSONConfigurationTransferMCT == nil {
		return nil, false
	}
	return v.rowIntersystemSONConfigurationTransferMCT, true
}
func (v MMEConfigurationTransferIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (MMEConfigurationTransferIEValue, error) {
	out := MMEConfigurationTransferIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(130):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value SONConfigurationTransfer
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "SONConfigurationTransferMCT:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SONConfigurationTransfer")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowSONConfigurationTransferMCT = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(295):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value ENDCSONConfigurationTransfer
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ENDCSONConfigurationTransferMCT:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENDCSONConfigurationTransfer")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowENDCSONConfigurationTransferMCT = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(309):
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
		out.rowIntersystemSONConfigurationTransferMCT = &value
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
func (v MMEConfigurationTransferIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v MMEConfigurationTransferIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(130):
		if v.rowSONConfigurationTransferMCT == nil {
			return nil, fmt.Errorf("%s missing value", "MMEConfigurationTransferIEs.id-SONConfigurationTransferMCT:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowSONConfigurationTransferMCT.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(295):
		if v.rowENDCSONConfigurationTransferMCT == nil {
			return nil, fmt.Errorf("%s missing value", "MMEConfigurationTransferIEs.id-EN-DCSONConfigurationTransfer-MCT:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowENDCSONConfigurationTransferMCT.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(309):
		if v.rowIntersystemSONConfigurationTransferMCT == nil {
			return nil, fmt.Errorf("%s missing value", "MMEConfigurationTransferIEs.id-IntersystemSONConfigurationTransferMCT:")
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
		})(*v.rowIntersystemSONConfigurationTransferMCT, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "MMEConfigurationTransferIEValue:", v.id)
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
	return SONConfigurationTransferExtIEsSynchronisationInformationExtBinding{info: t.infoSynchronisationInformation(), codec: func() s40.SynchronisationInformationValueCodec {
		sealed := s40.SynchronisationInformationValueCodec{}
		*s40.BridgeSynchronisationInformationValueCodecFieldPath(&sealed) = "SynchronisationInformation"
		*s40.BridgeSynchronisationInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s40.SynchronisationInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s40.SynchronisationInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SynchronisationInformation")
			var zero SONConfigurationTransferExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(209), raw)
			if err != nil {
				var empty s40.SynchronisationInformation
				return empty, runtime.WrapDecodePath(err, "SynchronisationInformation")
			}
			value, ok := decoded.AsSynchronisationInformation()
			if !ok {
				var empty s40.SynchronisationInformation
				return empty, fmt.Errorf("binding SONConfigurationTransfer-ExtIEs.id-Synchronisation-Information: no selected value")
			}
			return *value, nil
		}
		*s40.BridgeSynchronisationInformationValueCodecFieldEncode(&sealed) = func(value s40.SynchronisationInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SONConfigurationTransferExtIEsValue{id: s00.ProtocolIEID(209), rowSynchronisationInformation: &value}).encodeFresh(fresh, budget)
		}
		*s40.BridgeSynchronisationInformationValueCodecFieldCapture(&sealed) = func(v s40.SynchronisationInformation, options aper.DecodeState) (s40.SynchronisationInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s40.BridgeCaptureS1APSynchronisationInformation(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s40.BridgeSynchronisationInformationValueCodecFieldCompare(&sealed) = func(v s40.SynchronisationInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s40.BridgeCompareS1APSynchronisationInformation(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s40.BridgeSynchronisationInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SynchronisationInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s40.SynchronisationInformation) SONConfigurationTransferExtIEsValue {
			return SONConfigurationTransferExtIEsValue{id: s00.ProtocolIEID(209), rowSynchronisationInformation: &value}
		}, get: func(value *SONConfigurationTransferExtIEsValue) (*s40.SynchronisationInformation, bool) {
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
	return SONConfigurationTransferExtIEsRequestedTNLInfoExtBinding{info: t.infoRequestedTNLInfo(), codec: func() s31.RequestedTNLInfoValueCodec {
		sealed := s31.RequestedTNLInfoValueCodec{}
		*s31.BridgeRequestedTNLInfoValueCodecFieldPath(&sealed) = "RequestedTNLInfo"
		*s31.BridgeRequestedTNLInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.RequestedTNLInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.RequestedTNLInfo
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("RequestedTNLInfo")
			var zero SONConfigurationTransferExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(356), raw)
			if err != nil {
				var empty s31.RequestedTNLInfo
				return empty, runtime.WrapDecodePath(err, "RequestedTNLInfo")
			}
			value, ok := decoded.AsRequestedTNLInfo()
			if !ok {
				var empty s31.RequestedTNLInfo
				return empty, fmt.Errorf("binding SONConfigurationTransfer-ExtIEs.id-RequestedTNLInfo: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeRequestedTNLInfoValueCodecFieldEncode(&sealed) = func(value s31.RequestedTNLInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (SONConfigurationTransferExtIEsValue{id: s00.ProtocolIEID(356), rowRequestedTNLInfo: &value}).encodeFresh(fresh, budget)
		}
		*s31.BridgeRequestedTNLInfoValueCodecFieldCapture(&sealed) = func(v s31.RequestedTNLInfo, options aper.DecodeState) (s31.RequestedTNLInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s31.BridgeCaptureS1APRequestedTNLInfo(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeRequestedTNLInfoValueCodecFieldCompare(&sealed) = func(v s31.RequestedTNLInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APRequestedTNLInfo(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s31.BridgeRequestedTNLInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RequestedTNLInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.RequestedTNLInfo) SONConfigurationTransferExtIEsValue {
			return SONConfigurationTransferExtIEsValue{id: s00.ProtocolIEID(356), rowRequestedTNLInfo: &value}
		}, get: func(value *SONConfigurationTransferExtIEsValue) (*s31.RequestedTNLInfo, bool) {
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
func RequestedTNLInfoCodec() s31.RequestedTNLInfoValueCodec {
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
func SynchronisationInformationCodec() s40.SynchronisationInformationValueCodec {
	return SONConfigurationTransferExtIEs().SynchronisationInformation().Codec()
}

// X2TNLConfigurationInfoCodec binds the complete APER value type.
func X2TNLConfigurationInfoCodec() X2TNLConfigurationInfoValueCodec {
	return SONConfigurationTransferExtIEs().X2TNLConfigurationInfo().Codec()
}
func BridgeValidateHandoverRequestBudget(v *s60.HandoverRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil HandoverRequest")
	}
	rows := []s00.FieldInfo{s60.HandoverRequestIEs().MMEUES1APID().Info(), s60.HandoverRequestIEs().HandoverType().Info(), s60.HandoverRequestIEs().Cause().Info(), s60.HandoverRequestIEs().UEaggregateMaximumBitrate().Info(), s60.HandoverRequestIEs().ERABToBeSetupListHOReq().Info(), s60.HandoverRequestIEs().SourceToTargetTransparentContainer().Info(), s60.HandoverRequestIEs().UESecurityCapabilities().Info(), s60.HandoverRequestIEs().HandoverRestrictionList().Info(), s60.HandoverRequestIEs().TraceActivation().Info(), s60.HandoverRequestIEs().RequestType().Info(), s60.HandoverRequestIEs().SRVCCOperationPossible().Info(), s60.HandoverRequestIEs().SecurityContext().Info(), s60.HandoverRequestIEs().NASSecurityParameterstoEUTRAN().Info(), s60.HandoverRequestIEs().CSGId().Info(), s60.HandoverRequestIEs().CSGMembershipStatus().Info(), s60.HandoverRequestIEs().GUMMEIID().Info(), s60.HandoverRequestIEs().MMEUES1APID2().Info(), s60.HandoverRequestIEs().ManagementBasedMDTAllowed().Info(), s60.HandoverRequestIEs().ManagementBasedMDTPLMNList().Info(), s60.HandoverRequestIEs().MaskedIMEISV().Info(), s60.HandoverRequestIEs().ExpectedUEBehaviour().Info(), s60.HandoverRequestIEs().ProSeAuthorized().Info(), s60.HandoverRequestIEs().UEUserPlaneCIoTSupportIndicator().Info(), s60.HandoverRequestIEs().V2XServicesAuthorized().Info(), s60.HandoverRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s60.HandoverRequestIEs().EnhancedCoverageRestricted().Info(), s60.HandoverRequestIEs().NRUESecurityCapabilities().Info(), s60.HandoverRequestIEs().CEModeBRestricted().Info(), s60.HandoverRequestIEs().AerialUEsubscriptionInformation().Info(), s60.HandoverRequestIEs().PendingDataIndication().Info(), s60.HandoverRequestIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s60.HandoverRequestIEs().AdditionalRRMPriorityIndex().Info(), s60.HandoverRequestIEs().IABAuthorized().Info(), s60.HandoverRequestIEs().NRV2XServicesAuthorized().Info(), s60.HandoverRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s60.HandoverRequestIEs().PC5QoSParameters().Info(), s60.HandoverRequestIEs().UERadioCapabilityID().Info(), s60.HandoverRequestIEs().TimeRefDistribution().Info()}
	report := s60.BridgeHandoverRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "HandoverRequest.protocolIEs", budget)
	BridgeWalkValidationHandoverRequest(v, &report, "HandoverRequest", true)
	return report, nil
}
func BridgeValidateInitialContextSetupRequestBudget(v *s60.InitialContextSetupRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil InitialContextSetupRequest")
	}
	rows := []s00.FieldInfo{s60.InitialContextSetupRequestIEs().MMEUES1APID().Info(), s60.InitialContextSetupRequestIEs().ENBUES1APID().Info(), s60.InitialContextSetupRequestIEs().UEaggregateMaximumBitrate().Info(), s60.InitialContextSetupRequestIEs().ERABToBeSetupListCtxtSUReq().Info(), s60.InitialContextSetupRequestIEs().UESecurityCapabilities().Info(), s60.InitialContextSetupRequestIEs().SecurityKey().Info(), s60.InitialContextSetupRequestIEs().TraceActivation().Info(), s60.InitialContextSetupRequestIEs().HandoverRestrictionList().Info(), s60.InitialContextSetupRequestIEs().UERadioCapability().Info(), s60.InitialContextSetupRequestIEs().SubscriberProfileIDforRFP().Info(), s60.InitialContextSetupRequestIEs().CSFallbackIndicator().Info(), s60.InitialContextSetupRequestIEs().SRVCCOperationPossible().Info(), s60.InitialContextSetupRequestIEs().CSGMembershipStatus().Info(), s60.InitialContextSetupRequestIEs().RegisteredLAI().Info(), s60.InitialContextSetupRequestIEs().GUMMEIID().Info(), s60.InitialContextSetupRequestIEs().MMEUES1APID2().Info(), s60.InitialContextSetupRequestIEs().ManagementBasedMDTAllowed().Info(), s60.InitialContextSetupRequestIEs().ManagementBasedMDTPLMNList().Info(), s60.InitialContextSetupRequestIEs().AdditionalCSFallbackIndicator().Info(), s60.InitialContextSetupRequestIEs().MaskedIMEISV().Info(), s60.InitialContextSetupRequestIEs().ExpectedUEBehaviour().Info(), s60.InitialContextSetupRequestIEs().ProSeAuthorized().Info(), s60.InitialContextSetupRequestIEs().UEUserPlaneCIoTSupportIndicator().Info(), s60.InitialContextSetupRequestIEs().V2XServicesAuthorized().Info(), s60.InitialContextSetupRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s60.InitialContextSetupRequestIEs().EnhancedCoverageRestricted().Info(), s60.InitialContextSetupRequestIEs().NRUESecurityCapabilities().Info(), s60.InitialContextSetupRequestIEs().CEModeBRestricted().Info(), s60.InitialContextSetupRequestIEs().AerialUEsubscriptionInformation().Info(), s60.InitialContextSetupRequestIEs().PendingDataIndication().Info(), s60.InitialContextSetupRequestIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s60.InitialContextSetupRequestIEs().AdditionalRRMPriorityIndex().Info(), s60.InitialContextSetupRequestIEs().IABAuthorized().Info(), s60.InitialContextSetupRequestIEs().NRV2XServicesAuthorized().Info(), s60.InitialContextSetupRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s60.InitialContextSetupRequestIEs().PC5QoSParameters().Info(), s60.InitialContextSetupRequestIEs().UERadioCapabilityID().Info(), s60.InitialContextSetupRequestIEs().CoarseUELocation().Info(), s60.InitialContextSetupRequestIEs().TimeRefDistribution().Info()}
	report := s60.BridgeInitialContextSetupRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "InitialContextSetupRequest.protocolIEs", budget)
	BridgeWalkValidationInitialContextSetupRequest(v, &report, "InitialContextSetupRequest", true)
	return report, nil
}
func BridgeValidatePagingBudget(v *s61.Paging, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil Paging")
	}
	rows := []s00.FieldInfo{s61.PagingIEs().UEIdentityIndexValue().Info(), s61.PagingIEs().UEPagingID().Info(), s61.PagingIEs().PagingDRX().Info(), s61.PagingIEs().CNDomain().Info(), s61.PagingIEs().TAIList().Info(), s61.PagingIEs().CSGIdList().Info(), s61.PagingIEs().PagingPriority().Info(), s61.PagingIEs().UERadioCapabilityForPaging().Info(), s61.PagingIEs().AssistanceDataForPaging().Info(), s61.PagingIEs().PagingEDRXInformation().Info(), s61.PagingIEs().ExtendedUEIdentityIndexValue().Info(), s61.PagingIEs().NBIoTPagingEDRXInformation().Info(), s61.PagingIEs().NBIoTUEIdentityIndexValue().Info(), s61.PagingIEs().EnhancedCoverageRestricted().Info(), s61.PagingIEs().CEModeBRestricted().Info(), s61.PagingIEs().DataSize().Info(), s61.PagingIEs().WUSAssistanceInformation().Info(), s61.PagingIEs().NBIoTPagingDRX().Info(), s61.PagingIEs().PagingCause().Info()}
	report := s61.BridgePagingIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "Paging.protocolIEs", budget)
	BridgeWalkValidationPaging(v, &report, "Paging", true)
	return report, nil
}
func BridgeValidateUEContextModificationRequestBudget(v *s58.UEContextModificationRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil UEContextModificationRequest")
	}
	rows := []s00.FieldInfo{s58.UEContextModificationRequestIEs().MMEUES1APID().Info(), s58.UEContextModificationRequestIEs().ENBUES1APID().Info(), s58.UEContextModificationRequestIEs().SecurityKey().Info(), s58.UEContextModificationRequestIEs().SubscriberProfileIDforRFP().Info(), s58.UEContextModificationRequestIEs().UEaggregateMaximumBitrate().Info(), s58.UEContextModificationRequestIEs().CSFallbackIndicator().Info(), s58.UEContextModificationRequestIEs().UESecurityCapabilities().Info(), s58.UEContextModificationRequestIEs().CSGMembershipStatus().Info(), s58.UEContextModificationRequestIEs().RegisteredLAI().Info(), s58.UEContextModificationRequestIEs().AdditionalCSFallbackIndicator().Info(), s58.UEContextModificationRequestIEs().ProSeAuthorized().Info(), s58.UEContextModificationRequestIEs().SRVCCOperationPossible().Info(), s58.UEContextModificationRequestIEs().SRVCCOperationNotPossible().Info(), s58.UEContextModificationRequestIEs().V2XServicesAuthorized().Info(), s58.UEContextModificationRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s58.UEContextModificationRequestIEs().NRUESecurityCapabilities().Info(), s58.UEContextModificationRequestIEs().AerialUEsubscriptionInformation().Info(), s58.UEContextModificationRequestIEs().AdditionalRRMPriorityIndex().Info(), s58.UEContextModificationRequestIEs().IABAuthorized().Info(), s58.UEContextModificationRequestIEs().NRV2XServicesAuthorized().Info(), s58.UEContextModificationRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s58.UEContextModificationRequestIEs().PC5QoSParameters().Info(), s58.UEContextModificationRequestIEs().UERadioCapabilityID().Info(), s58.UEContextModificationRequestIEs().TimeRefDistribution().Info()}
	report := s58.BridgeUEContextModificationRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "UEContextModificationRequest.protocolIEs", budget)
	BridgeWalkValidationUEContextModificationRequest(v, &report, "UEContextModificationRequest", true)
	return report, nil
}
func BridgeValidateTraceStartBudget(v *s61.TraceStart, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil TraceStart")
	}
	rows := []s00.FieldInfo{s60.TraceStartIEs().MMEUES1APID().Info(), s60.TraceStartIEs().ENBUES1APID().Info(), s60.TraceStartIEs().TraceActivation().Info()}
	report := s61.BridgeTraceStartIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "TraceStart.protocolIEs", budget)
	BridgeWalkValidationTraceStart(v, &report, "TraceStart", true)
	return report, nil
}
func BridgeValidateWriteReplaceWarningRequestBudget(v *WriteReplaceWarningRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil WriteReplaceWarningRequest")
	}
	rows := []s00.FieldInfo{s42.WriteReplaceWarningRequestIEs().MessageIdentifier().Info(), s42.WriteReplaceWarningRequestIEs().SerialNumber().Info(), s42.WriteReplaceWarningRequestIEs().WarningAreaList().Info(), s42.WriteReplaceWarningRequestIEs().RepetitionPeriod().Info(), s42.WriteReplaceWarningRequestIEs().ExtendedRepetitionPeriod().Info(), s42.WriteReplaceWarningRequestIEs().NumberofBroadcastRequest().Info(), s42.WriteReplaceWarningRequestIEs().WarningType().Info(), s42.WriteReplaceWarningRequestIEs().WarningSecurityInfo().Info(), s42.WriteReplaceWarningRequestIEs().DataCodingScheme().Info(), s42.WriteReplaceWarningRequestIEs().WarningMessageContents().Info(), s42.WriteReplaceWarningRequestIEs().ConcurrentWarningMessageIndicator().Info(), s42.WriteReplaceWarningRequestIEs().WarningAreaCoordinates().Info()}
	report := BridgeWriteReplaceWarningRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "WriteReplaceWarningRequest.protocolIEs", budget)
	BridgeWalkValidationWriteReplaceWarningRequest(v, &report, "WriteReplaceWarningRequest", true)
	return report, nil
}
func BridgeValidateWriteReplaceWarningResponseBudget(v *WriteReplaceWarningResponse, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil WriteReplaceWarningResponse")
	}
	rows := []s00.FieldInfo{s41.WriteReplaceWarningResponseIEs().MessageIdentifier().Info(), s41.WriteReplaceWarningResponseIEs().SerialNumber().Info(), s41.WriteReplaceWarningResponseIEs().BroadcastCompletedAreaList().Info(), s41.WriteReplaceWarningResponseIEs().CriticalityDiagnostics().Info()}
	report := BridgeWriteReplaceWarningResponseIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "WriteReplaceWarningResponse.protocolIEs", budget)
	BridgeWalkValidationWriteReplaceWarningResponse(v, &report, "WriteReplaceWarningResponse", true)
	return report, nil
}
func BridgeValidateKillRequestBudget(v *s42.KillRequest, budget *aper.DecodeBudget,

) (s25.ValidationReport, error) {
	if v == nil {
		return func() s25.ValidationReport {
			sealed := s25.ValidationReport{}
			*s25.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil KillRequest")
	}
	rows := []s00.FieldInfo{s42.KillRequestIEs().MessageIdentifier().Info(), s42.KillRequestIEs().SerialNumber().Info(), s42.KillRequestIEs().WarningAreaList().Info(), s42.KillRequestIEs().KillAllWarningMessages().Info()}
	report := s42.BridgeKillRequestIEValueValidateS1APIEContainer(v.ProtocolIEs, rows, "KillRequest.protocolIEs", budget)
	BridgeWalkValidationKillRequest(v, &report, "KillRequest", true)
	return report, nil
}
func ValidateHandoverRequest(v *s60.HandoverRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "HandoverRequest")
	}
	report, err := BridgeValidateHandoverRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s60.BridgeHandoverRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "HandoverRequest")
}
func ValidateInitialContextSetupRequest(v *s60.InitialContextSetupRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "InitialContextSetupRequest")
	}
	report, err := BridgeValidateInitialContextSetupRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s60.BridgeInitialContextSetupRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "InitialContextSetupRequest")
}
func ValidatePaging(v *s61.Paging, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "Paging")
	}
	report, err := BridgeValidatePagingBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s61.BridgePagingMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "Paging")
}
func ValidateUEContextModificationRequest(v *s58.UEContextModificationRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "UEContextModificationRequest")
	}
	report, err := BridgeValidateUEContextModificationRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s58.BridgeUEContextModificationRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextModificationRequest")
}
func ValidateTraceStart(v *s61.TraceStart, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "TraceStart")
	}
	report, err := BridgeValidateTraceStartBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s61.BridgeTraceStartMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "TraceStart")
}
func ValidateWriteReplaceWarningRequest(v *WriteReplaceWarningRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "WriteReplaceWarningRequest")
	}
	report, err := BridgeValidateWriteReplaceWarningRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = v.marshalAPERBudget(budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "WriteReplaceWarningRequest")
}
func ValidateWriteReplaceWarningResponse(v *WriteReplaceWarningResponse, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "WriteReplaceWarningResponse")
	}
	report, err := BridgeValidateWriteReplaceWarningResponseBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = v.marshalAPERBudget(budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "WriteReplaceWarningResponse")
}
func ValidateKillRequest(v *s42.KillRequest, options ...aper.ValidationOption) (s25.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s25.ValidationReport{}, aper.OperationError(err, "KillRequest")
	}
	report, err := BridgeValidateKillRequestBudget(v, budget)
	if err == nil && !s58.BridgeValidationHasValueMismatch(report) {
		_, err = s42.BridgeKillRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		err = *s25.BridgeValidationReportFieldErr(&report)
	}
	*s25.BridgeValidationReportFieldBudget(&report) = nil
	*s25.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "KillRequest")
}
func BridgeWalkValidationHandoverRequest(v *s60.HandoverRequest, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s60.HandoverRequestIEs().MMEUES1APID().Info(), s60.HandoverRequestIEs().HandoverType().Info(), s60.HandoverRequestIEs().Cause().Info(), s60.HandoverRequestIEs().UEaggregateMaximumBitrate().Info(), s60.HandoverRequestIEs().ERABToBeSetupListHOReq().Info(), s60.HandoverRequestIEs().SourceToTargetTransparentContainer().Info(), s60.HandoverRequestIEs().UESecurityCapabilities().Info(), s60.HandoverRequestIEs().HandoverRestrictionList().Info(), s60.HandoverRequestIEs().TraceActivation().Info(), s60.HandoverRequestIEs().RequestType().Info(), s60.HandoverRequestIEs().SRVCCOperationPossible().Info(), s60.HandoverRequestIEs().SecurityContext().Info(), s60.HandoverRequestIEs().NASSecurityParameterstoEUTRAN().Info(), s60.HandoverRequestIEs().CSGId().Info(), s60.HandoverRequestIEs().CSGMembershipStatus().Info(), s60.HandoverRequestIEs().GUMMEIID().Info(), s60.HandoverRequestIEs().MMEUES1APID2().Info(), s60.HandoverRequestIEs().ManagementBasedMDTAllowed().Info(), s60.HandoverRequestIEs().ManagementBasedMDTPLMNList().Info(), s60.HandoverRequestIEs().MaskedIMEISV().Info(), s60.HandoverRequestIEs().ExpectedUEBehaviour().Info(), s60.HandoverRequestIEs().ProSeAuthorized().Info(), s60.HandoverRequestIEs().UEUserPlaneCIoTSupportIndicator().Info(), s60.HandoverRequestIEs().V2XServicesAuthorized().Info(), s60.HandoverRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s60.HandoverRequestIEs().EnhancedCoverageRestricted().Info(), s60.HandoverRequestIEs().NRUESecurityCapabilities().Info(), s60.HandoverRequestIEs().CEModeBRestricted().Info(), s60.HandoverRequestIEs().AerialUEsubscriptionInformation().Info(), s60.HandoverRequestIEs().PendingDataIndication().Info(), s60.HandoverRequestIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s60.HandoverRequestIEs().AdditionalRRMPriorityIndex().Info(), s60.HandoverRequestIEs().IABAuthorized().Info(), s60.HandoverRequestIEs().NRV2XServicesAuthorized().Info(), s60.HandoverRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s60.HandoverRequestIEs().PC5QoSParameters().Info(), s60.HandoverRequestIEs().UERadioCapabilityID().Info(), s60.HandoverRequestIEs().TimeRefDistribution().Info()}
			s30.BridgeMergeNestedValidation(report, s60.BridgeHandoverRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					s63.BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(53):
				if value, ok := fields[i].Value.AsERABToBeSetupListHOReq(); ok {
					s62.BridgeWalkValidationERABToBeSetupListHOReq(value, report, fmt.Sprintf("%s[%d]{id=53}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(107):
				if value, ok := fields[i].Value.AsUESecurityCapabilities(); ok {
					s63.BridgeWalkValidationUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=107}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(41):
				if value, ok := fields[i].Value.AsHandoverRestrictionList(); ok {
					s62.BridgeWalkValidationHandoverRestrictionList(value, report, fmt.Sprintf("%s[%d]{id=41}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(25):
				if value, ok := fields[i].Value.AsTraceActivation(); ok {
					BridgeWalkValidationTraceActivation(value, report, fmt.Sprintf("%s[%d]{id=25}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(98):
				if value, ok := fields[i].Value.AsRequestType(); ok {
					s62.BridgeWalkValidationRequestType(value, report, fmt.Sprintf("%s[%d]{id=98}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(40):
				if value, ok := fields[i].Value.AsSecurityContext(); ok {
					s62.BridgeWalkValidationSecurityContext(value, report, fmt.Sprintf("%s[%d]{id=40}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(75):
				if value, ok := fields[i].Value.AsGUMMEIID(); ok {
					s61.BridgeWalkValidationGUMMEI(value, report, fmt.Sprintf("%s[%d]{id=75}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(177):
				if value, ok := fields[i].Value.AsManagementBasedMDTPLMNList(); ok {
					s62.BridgeWalkValidationMDTPLMNList(value, report, fmt.Sprintf("%s[%d]{id=177}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(196):
				if value, ok := fields[i].Value.AsExpectedUEBehaviour(); ok {
					s61.BridgeWalkValidationExpectedUEBehaviour(value, report, fmt.Sprintf("%s[%d]{id=196}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(195):
				if value, ok := fields[i].Value.AsProSeAuthorized(); ok {
					s62.BridgeWalkValidationProSeAuthorized(value, report, fmt.Sprintf("%s[%d]{id=195}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(240):
				if value, ok := fields[i].Value.AsV2XServicesAuthorized(); ok {
					s63.BridgeWalkValidationV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=240}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(248):
				if value, ok := fields[i].Value.AsUESidelinkAggregateMaximumBitrate(); ok {
					s63.BridgeWalkValidationUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=248}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(269):
				if value, ok := fields[i].Value.AsNRUESecurityCapabilities(); ok {
					s62.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					s62.BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
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
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationImmediateMDT(v *s59.ImmediateMDT, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.M1thresholdeventA2 != nil {
		s62.BridgeWalkValidationM1ThresholdEventA2(v.M1thresholdeventA2, report, path+".m1thresholdeventA2", false)
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.M1periodicReporting != nil {
		s62.BridgeWalkValidationM1PeriodicReporting(v.M1periodicReporting, report, path+".m1periodicReporting", false)
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s59.ImmediateMDTExtIEs().M3Configuration().Info()), s00.FieldInfo(s59.ImmediateMDTExtIEs().M4Configuration().Info()), s00.FieldInfo(s59.ImmediateMDTExtIEs().M5Configuration().Info()), s00.FieldInfo(s59.ImmediateMDTExtIEs().MDTLocationInfo().Info()), s00.FieldInfo(s59.ImmediateMDTExtIEs().M6Configuration().Info()), s00.FieldInfo(s59.ImmediateMDTExtIEs().M7Configuration().Info()), s00.FieldInfo(s59.ImmediateMDTExtIEs().BluetoothMeasurementConfiguration().Info()), s00.FieldInfo(s59.ImmediateMDTExtIEs().WLANMeasurementConfiguration().Info()), s00.FieldInfo(s59.ImmediateMDTExtIEs().SensorMeasurementConfiguration().Info())}
				s30.BridgeMergeNestedValidation(report, s59.BridgeImmediateMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(171):
					if value, ok := fields[i].ExtensionValue.AsM3Configuration(); ok {
						s62.BridgeWalkValidationM3Configuration(value, report, fmt.Sprintf("%s[%d]{id=171}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(172):
					if value, ok := fields[i].ExtensionValue.AsM4Configuration(); ok {
						s62.BridgeWalkValidationM4Configuration(value, report, fmt.Sprintf("%s[%d]{id=172}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(173):
					if value, ok := fields[i].ExtensionValue.AsM5Configuration(); ok {
						s62.BridgeWalkValidationM5Configuration(value, report, fmt.Sprintf("%s[%d]{id=173}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(220):
					if value, ok := fields[i].ExtensionValue.AsM6Configuration(); ok {
						s62.BridgeWalkValidationM6Configuration(value, report, fmt.Sprintf("%s[%d]{id=220}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(221):
					if value, ok := fields[i].ExtensionValue.AsM7Configuration(); ok {
						s62.BridgeWalkValidationM7Configuration(value, report, fmt.Sprintf("%s[%d]{id=221}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(284):
					if value, ok := fields[i].ExtensionValue.AsBluetoothMeasurementConfiguration(); ok {
						s61.BridgeWalkValidationBluetoothMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=284}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(285):
					if value, ok := fields[i].ExtensionValue.AsWLANMeasurementConfiguration(); ok {
						BridgeWalkValidationWLANMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=285}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(345):
					if value, ok := fields[i].ExtensionValue.AsSensorMeasurementConfiguration(); ok {
						s62.BridgeWalkValidationSensorMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=345}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInitialContextSetupRequest(v *s60.InitialContextSetupRequest, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s60.InitialContextSetupRequestIEs().MMEUES1APID().Info(), s60.InitialContextSetupRequestIEs().ENBUES1APID().Info(), s60.InitialContextSetupRequestIEs().UEaggregateMaximumBitrate().Info(), s60.InitialContextSetupRequestIEs().ERABToBeSetupListCtxtSUReq().Info(), s60.InitialContextSetupRequestIEs().UESecurityCapabilities().Info(), s60.InitialContextSetupRequestIEs().SecurityKey().Info(), s60.InitialContextSetupRequestIEs().TraceActivation().Info(), s60.InitialContextSetupRequestIEs().HandoverRestrictionList().Info(), s60.InitialContextSetupRequestIEs().UERadioCapability().Info(), s60.InitialContextSetupRequestIEs().SubscriberProfileIDforRFP().Info(), s60.InitialContextSetupRequestIEs().CSFallbackIndicator().Info(), s60.InitialContextSetupRequestIEs().SRVCCOperationPossible().Info(), s60.InitialContextSetupRequestIEs().CSGMembershipStatus().Info(), s60.InitialContextSetupRequestIEs().RegisteredLAI().Info(), s60.InitialContextSetupRequestIEs().GUMMEIID().Info(), s60.InitialContextSetupRequestIEs().MMEUES1APID2().Info(), s60.InitialContextSetupRequestIEs().ManagementBasedMDTAllowed().Info(), s60.InitialContextSetupRequestIEs().ManagementBasedMDTPLMNList().Info(), s60.InitialContextSetupRequestIEs().AdditionalCSFallbackIndicator().Info(), s60.InitialContextSetupRequestIEs().MaskedIMEISV().Info(), s60.InitialContextSetupRequestIEs().ExpectedUEBehaviour().Info(), s60.InitialContextSetupRequestIEs().ProSeAuthorized().Info(), s60.InitialContextSetupRequestIEs().UEUserPlaneCIoTSupportIndicator().Info(), s60.InitialContextSetupRequestIEs().V2XServicesAuthorized().Info(), s60.InitialContextSetupRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s60.InitialContextSetupRequestIEs().EnhancedCoverageRestricted().Info(), s60.InitialContextSetupRequestIEs().NRUESecurityCapabilities().Info(), s60.InitialContextSetupRequestIEs().CEModeBRestricted().Info(), s60.InitialContextSetupRequestIEs().AerialUEsubscriptionInformation().Info(), s60.InitialContextSetupRequestIEs().PendingDataIndication().Info(), s60.InitialContextSetupRequestIEs().SubscriptionBasedUEDifferentiationInfo().Info(), s60.InitialContextSetupRequestIEs().AdditionalRRMPriorityIndex().Info(), s60.InitialContextSetupRequestIEs().IABAuthorized().Info(), s60.InitialContextSetupRequestIEs().NRV2XServicesAuthorized().Info(), s60.InitialContextSetupRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s60.InitialContextSetupRequestIEs().PC5QoSParameters().Info(), s60.InitialContextSetupRequestIEs().UERadioCapabilityID().Info(), s60.InitialContextSetupRequestIEs().CoarseUELocation().Info(), s60.InitialContextSetupRequestIEs().TimeRefDistribution().Info()}
			s30.BridgeMergeNestedValidation(report, s60.BridgeInitialContextSetupRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					s63.BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(24):
				if value, ok := fields[i].Value.AsERABToBeSetupListCtxtSUReq(); ok {
					s62.BridgeWalkValidationERABToBeSetupListCtxtSUReq(value, report, fmt.Sprintf("%s[%d]{id=24}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(107):
				if value, ok := fields[i].Value.AsUESecurityCapabilities(); ok {
					s63.BridgeWalkValidationUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=107}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(25):
				if value, ok := fields[i].Value.AsTraceActivation(); ok {
					BridgeWalkValidationTraceActivation(value, report, fmt.Sprintf("%s[%d]{id=25}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(41):
				if value, ok := fields[i].Value.AsHandoverRestrictionList(); ok {
					s62.BridgeWalkValidationHandoverRestrictionList(value, report, fmt.Sprintf("%s[%d]{id=41}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(159):
				if value, ok := fields[i].Value.AsRegisteredLAI(); ok {
					s62.BridgeWalkValidationLAI(value, report, fmt.Sprintf("%s[%d]{id=159}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(75):
				if value, ok := fields[i].Value.AsGUMMEIID(); ok {
					s61.BridgeWalkValidationGUMMEI(value, report, fmt.Sprintf("%s[%d]{id=75}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(177):
				if value, ok := fields[i].Value.AsManagementBasedMDTPLMNList(); ok {
					s62.BridgeWalkValidationMDTPLMNList(value, report, fmt.Sprintf("%s[%d]{id=177}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(196):
				if value, ok := fields[i].Value.AsExpectedUEBehaviour(); ok {
					s61.BridgeWalkValidationExpectedUEBehaviour(value, report, fmt.Sprintf("%s[%d]{id=196}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(195):
				if value, ok := fields[i].Value.AsProSeAuthorized(); ok {
					s62.BridgeWalkValidationProSeAuthorized(value, report, fmt.Sprintf("%s[%d]{id=195}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(240):
				if value, ok := fields[i].Value.AsV2XServicesAuthorized(); ok {
					s63.BridgeWalkValidationV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=240}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(248):
				if value, ok := fields[i].Value.AsUESidelinkAggregateMaximumBitrate(); ok {
					s63.BridgeWalkValidationUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=248}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(269):
				if value, ok := fields[i].Value.AsNRUESecurityCapabilities(); ok {
					s62.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(278):
				if value, ok := fields[i].Value.AsSubscriptionBasedUEDifferentiationInfo(); ok {
					s62.BridgeWalkValidationSubscriptionBasedUEDifferentiationInfo(value, report, fmt.Sprintf("%s[%d]{id=278}", nestedPath, i), false)
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
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationKillRequest(v *s42.KillRequest, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s42.KillRequestIEs().MessageIdentifier().Info(), s42.KillRequestIEs().SerialNumber().Info(), s42.KillRequestIEs().WarningAreaList().Info(), s42.KillRequestIEs().KillAllWarningMessages().Info()}
			s30.BridgeMergeNestedValidation(report, s42.BridgeKillRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationLoggedMDT(v *s59.LoggedMDT, report *s25.ValidationReport, path string, skipRoot bool) {
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
				rows := []s00.FieldInfo{s00.FieldInfo(s59.LoggedMDTExtIEs().BluetoothMeasurementConfiguration().Info()), s00.FieldInfo(s59.LoggedMDTExtIEs().WLANMeasurementConfiguration().Info()), s00.FieldInfo(s59.LoggedMDTExtIEs().LoggedMDTTrigger().Info()), s00.FieldInfo(s59.LoggedMDTExtIEs().SensorMeasurementConfiguration().Info())}
				s30.BridgeMergeNestedValidation(report, s59.BridgeLoggedMDTExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(284):
					if value, ok := fields[i].ExtensionValue.AsBluetoothMeasurementConfiguration(); ok {
						s61.BridgeWalkValidationBluetoothMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=284}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(285):
					if value, ok := fields[i].ExtensionValue.AsWLANMeasurementConfiguration(); ok {
						BridgeWalkValidationWLANMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=285}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(344):
					if value, ok := fields[i].ExtensionValue.AsLoggedMDTTrigger(); ok {
						s62.BridgeWalkValidationLoggedMDTTrigger(value, report, fmt.Sprintf("%s[%d]{id=344}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(345):
					if value, ok := fields[i].ExtensionValue.AsSensorMeasurementConfiguration(); ok {
						s62.BridgeWalkValidationSensorMeasurementConfiguration(value, report, fmt.Sprintf("%s[%d]{id=345}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMDTConfiguration(v *s59.MDTConfiguration, report *s25.ValidationReport, path string, skipRoot bool) {
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
	s63.BridgeWalkValidationAreaScopeOfMDT(&v.AreaScopeOfMDT, report, path+".areaScopeOfMDT", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationMDTMode(&v.MDTMode, report, path+".mDTMode", false)
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s00.FieldInfo(s52.MDTConfigurationExtIEs().SignallingBasedMDTPLMNList().Info())}
				s30.BridgeMergeNestedValidation(report, s52.BridgeMDTConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(178):
					if value, ok := fields[i].ExtensionValue.AsSignallingBasedMDTPLMNList(); ok {
						s62.BridgeWalkValidationMDTPLMNList(value, report, fmt.Sprintf("%s[%d]{id=178}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationMDTMode(v *s59.MDTMode, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
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
		s62.BridgeWalkValidationMDTModeExtension(v.MDTModeExtension, report, path+".mDTMode-Extension", false)
	}
}
func BridgeWalkValidationPaging(v *s61.Paging, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s61.PagingIEs().UEIdentityIndexValue().Info(), s61.PagingIEs().UEPagingID().Info(), s61.PagingIEs().PagingDRX().Info(), s61.PagingIEs().CNDomain().Info(), s61.PagingIEs().TAIList().Info(), s61.PagingIEs().CSGIdList().Info(), s61.PagingIEs().PagingPriority().Info(), s61.PagingIEs().UERadioCapabilityForPaging().Info(), s61.PagingIEs().AssistanceDataForPaging().Info(), s61.PagingIEs().PagingEDRXInformation().Info(), s61.PagingIEs().ExtendedUEIdentityIndexValue().Info(), s61.PagingIEs().NBIoTPagingEDRXInformation().Info(), s61.PagingIEs().NBIoTUEIdentityIndexValue().Info(), s61.PagingIEs().EnhancedCoverageRestricted().Info(), s61.PagingIEs().CEModeBRestricted().Info(), s61.PagingIEs().DataSize().Info(), s61.PagingIEs().WUSAssistanceInformation().Info(), s61.PagingIEs().NBIoTPagingDRX().Info(), s61.PagingIEs().PagingCause().Info()}
			s30.BridgeMergeNestedValidation(report, s61.BridgePagingIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(43):
				if value, ok := fields[i].Value.AsUEPagingID(); ok {
					s63.BridgeWalkValidationUEPagingID(value, report, fmt.Sprintf("%s[%d]{id=43}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(46):
				if value, ok := fields[i].Value.AsTAIList(); ok {
					s63.BridgeWalkValidationTAIList(value, report, fmt.Sprintf("%s[%d]{id=46}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(128):
				if value, ok := fields[i].Value.AsCSGIdList(); ok {
					s61.BridgeWalkValidationCSGIdList(value, report, fmt.Sprintf("%s[%d]{id=128}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(211):
				if value, ok := fields[i].Value.AsAssistanceDataForPaging(); ok {
					s62.BridgeWalkValidationAssistanceDataForPaging(value, report, fmt.Sprintf("%s[%d]{id=211}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(227):
				if value, ok := fields[i].Value.AsPagingEDRXInformation(); ok {
					s62.BridgeWalkValidationPagingEDRXInformation(value, report, fmt.Sprintf("%s[%d]{id=227}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(239):
				if value, ok := fields[i].Value.AsNBIoTPagingEDRXInformation(); ok {
					s62.BridgeWalkValidationNBIoTPagingEDRXInformation(value, report, fmt.Sprintf("%s[%d]{id=239}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(323):
				if value, ok := fields[i].Value.AsWUSAssistanceInformation(); ok {
					BridgeWalkValidationWUSAssistanceInformation(value, report, fmt.Sprintf("%s[%d]{id=323}", nestedPath, i), false)
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationSuccessfulOutcome(v *SuccessfulOutcome, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationTraceActivation(v *s59.TraceActivation, report *s25.ValidationReport, path string, skipRoot bool) {
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
				rows := []s00.FieldInfo{s00.FieldInfo(s59.TraceActivationExtIEs().MDTConfiguration().Info()), s00.FieldInfo(s59.TraceActivationExtIEs().UEAppLayerMeasConfig().Info()), s00.FieldInfo(s59.TraceActivationExtIEs().MDTConfigurationNR().Info()), s00.FieldInfo(s59.TraceActivationExtIEs().TraceCollectionEntityURI().Info())}
				s30.BridgeMergeNestedValidation(report, s61.BridgeTraceActivationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s25.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(162):
					if value, ok := fields[i].ExtensionValue.AsMDTConfiguration(); ok {
						BridgeWalkValidationMDTConfiguration(value, report, fmt.Sprintf("%s[%d]{id=162}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(262):
					if value, ok := fields[i].ExtensionValue.AsUEAppLayerMeasConfig(); ok {
						s63.BridgeWalkValidationUEAppLayerMeasConfig(value, report, fmt.Sprintf("%s[%d]{id=262}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationTraceStart(v *s61.TraceStart, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s60.TraceStartIEs().MMEUES1APID().Info(), s60.TraceStartIEs().ENBUES1APID().Info(), s60.TraceStartIEs().TraceActivation().Info()}
			s30.BridgeMergeNestedValidation(report, s61.BridgeTraceStartIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationUEContextModificationRequest(v *s58.UEContextModificationRequest, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s58.UEContextModificationRequestIEs().MMEUES1APID().Info(), s58.UEContextModificationRequestIEs().ENBUES1APID().Info(), s58.UEContextModificationRequestIEs().SecurityKey().Info(), s58.UEContextModificationRequestIEs().SubscriberProfileIDforRFP().Info(), s58.UEContextModificationRequestIEs().UEaggregateMaximumBitrate().Info(), s58.UEContextModificationRequestIEs().CSFallbackIndicator().Info(), s58.UEContextModificationRequestIEs().UESecurityCapabilities().Info(), s58.UEContextModificationRequestIEs().CSGMembershipStatus().Info(), s58.UEContextModificationRequestIEs().RegisteredLAI().Info(), s58.UEContextModificationRequestIEs().AdditionalCSFallbackIndicator().Info(), s58.UEContextModificationRequestIEs().ProSeAuthorized().Info(), s58.UEContextModificationRequestIEs().SRVCCOperationPossible().Info(), s58.UEContextModificationRequestIEs().SRVCCOperationNotPossible().Info(), s58.UEContextModificationRequestIEs().V2XServicesAuthorized().Info(), s58.UEContextModificationRequestIEs().UESidelinkAggregateMaximumBitrate().Info(), s58.UEContextModificationRequestIEs().NRUESecurityCapabilities().Info(), s58.UEContextModificationRequestIEs().AerialUEsubscriptionInformation().Info(), s58.UEContextModificationRequestIEs().AdditionalRRMPriorityIndex().Info(), s58.UEContextModificationRequestIEs().IABAuthorized().Info(), s58.UEContextModificationRequestIEs().NRV2XServicesAuthorized().Info(), s58.UEContextModificationRequestIEs().NRUESidelinkAggregateMaximumBitrate().Info(), s58.UEContextModificationRequestIEs().PC5QoSParameters().Info(), s58.UEContextModificationRequestIEs().UERadioCapabilityID().Info(), s58.UEContextModificationRequestIEs().TimeRefDistribution().Info()}
			s30.BridgeMergeNestedValidation(report, s58.BridgeUEContextModificationRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(66):
				if value, ok := fields[i].Value.AsUEaggregateMaximumBitrate(); ok {
					s63.BridgeWalkValidationUEAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=66}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(107):
				if value, ok := fields[i].Value.AsUESecurityCapabilities(); ok {
					s63.BridgeWalkValidationUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=107}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(159):
				if value, ok := fields[i].Value.AsRegisteredLAI(); ok {
					s62.BridgeWalkValidationLAI(value, report, fmt.Sprintf("%s[%d]{id=159}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(195):
				if value, ok := fields[i].Value.AsProSeAuthorized(); ok {
					s62.BridgeWalkValidationProSeAuthorized(value, report, fmt.Sprintf("%s[%d]{id=195}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(240):
				if value, ok := fields[i].Value.AsV2XServicesAuthorized(); ok {
					s63.BridgeWalkValidationV2XServicesAuthorized(value, report, fmt.Sprintf("%s[%d]{id=240}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(248):
				if value, ok := fields[i].Value.AsUESidelinkAggregateMaximumBitrate(); ok {
					s63.BridgeWalkValidationUESidelinkAggregateMaximumBitrate(value, report, fmt.Sprintf("%s[%d]{id=248}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(269):
				if value, ok := fields[i].Value.AsNRUESecurityCapabilities(); ok {
					s62.BridgeWalkValidationNRUESecurityCapabilities(value, report, fmt.Sprintf("%s[%d]{id=269}", nestedPath, i), false)
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
			}
		}
	}
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationWLANMeasConfigNameList(v *s00.WLANMeasConfigNameList, report *s25.ValidationReport, path string, skipRoot bool) {
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
func BridgeWalkValidationWLANMeasurementConfiguration(v *s59.WLANMeasurementConfiguration, report *s25.ValidationReport, path string, skipRoot bool) {
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
	if v.WlanMeasConfigNameList != nil {
		BridgeWalkValidationWLANMeasConfigNameList(&v.WlanMeasConfigNameList, report, path+".wlanMeasConfigNameList", false)
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
				s30.BridgeMergeNestedValidation(report, s61.BridgeWLANMeasurementConfigurationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationWUSAssistanceInformation(v *s61.WUSAssistanceInformation, report *s25.ValidationReport, path string, skipRoot bool) {
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
				s30.BridgeMergeNestedValidation(report, s61.BridgeWUSAssistanceInformationExtIEsValueValidateS1APExtensionContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
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
func BridgeWalkValidationWarningAreaList(v *s41.WarningAreaList, report *s25.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s25.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s25.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.WarningAreaListChoiceCellIDList && v.CellIDList != nil {
		s61.BridgeWalkValidationECGIList(&v.CellIDList, report, path+".cellIDList", false)
	}
	if v.Choice == s00.WarningAreaListChoiceTrackingAreaListforWarning && v.TrackingAreaListforWarning != nil {
		s63.BridgeWalkValidationTAIListforWarning(&v.TrackingAreaListforWarning, report, path+".trackingAreaListforWarning", false)
	}
	if v.Choice == s00.WarningAreaListChoiceEmergencyAreaIDList && v.EmergencyAreaIDList != nil {
		s61.BridgeWalkValidationEmergencyAreaIDList(&v.EmergencyAreaIDList, report, path+".emergencyAreaIDList", false)
	}
}
func BridgeWalkValidationWriteReplaceWarningRequest(v *WriteReplaceWarningRequest, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s42.WriteReplaceWarningRequestIEs().MessageIdentifier().Info(), s42.WriteReplaceWarningRequestIEs().SerialNumber().Info(), s42.WriteReplaceWarningRequestIEs().WarningAreaList().Info(), s42.WriteReplaceWarningRequestIEs().RepetitionPeriod().Info(), s42.WriteReplaceWarningRequestIEs().ExtendedRepetitionPeriod().Info(), s42.WriteReplaceWarningRequestIEs().NumberofBroadcastRequest().Info(), s42.WriteReplaceWarningRequestIEs().WarningType().Info(), s42.WriteReplaceWarningRequestIEs().WarningSecurityInfo().Info(), s42.WriteReplaceWarningRequestIEs().DataCodingScheme().Info(), s42.WriteReplaceWarningRequestIEs().WarningMessageContents().Info(), s42.WriteReplaceWarningRequestIEs().ConcurrentWarningMessageIndicator().Info(), s42.WriteReplaceWarningRequestIEs().WarningAreaCoordinates().Info()}
			s30.BridgeMergeNestedValidation(report, BridgeWriteReplaceWarningRequestIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
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
	if *s25.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationWriteReplaceWarningResponse(v *WriteReplaceWarningResponse, report *s25.ValidationReport, path string, skipRoot bool) {
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
			rows := []s00.FieldInfo{s41.WriteReplaceWarningResponseIEs().MessageIdentifier().Info(), s41.WriteReplaceWarningResponseIEs().SerialNumber().Info(), s41.WriteReplaceWarningResponseIEs().BroadcastCompletedAreaList().Info(), s41.WriteReplaceWarningResponseIEs().CriticalityDiagnostics().Info()}
			s30.BridgeMergeNestedValidation(report, BridgeWriteReplaceWarningResponseIEValueValidateS1APIEContainer(fields, rows, nestedPath, *s25.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s25.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(120):
				if value, ok := fields[i].Value.AsBroadcastCompletedAreaList(); ok {
					s62.BridgeWalkValidationBroadcastCompletedAreaList(value, report, fmt.Sprintf("%s[%d]{id=120}", nestedPath, i), false)
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
func BridgeENBConfigurationTransferIEFieldFieldReplay(v *ENBConfigurationTransferIEField) *aper.Snapshot {
	return &v.replay
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
func BridgeENBConfigurationTransferIEValueFieldId(v *ENBConfigurationTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeENBConfigurationTransferIEValueFieldIsOpaque(v *ENBConfigurationTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeENBConfigurationTransferIEValueFieldOpaque(v *ENBConfigurationTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
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
func BridgeENBConfigurationTransferIEValueMethodEncodeFresh(v ENBConfigurationTransferIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeENBConfigurationTransferIEValueMethodMatchesID(v ENBConfigurationTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeENBConfigurationTransferIEValueMethodRule(v ENBConfigurationTransferIEValue) aper.SourceRule {
	return v.rule()
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
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldCapture(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *func(s28.ENBConfigurationUpdateAcknowledge, aper.DecodeState) (s28.ENBConfigurationUpdateAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldCompare(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *func(s28.ENBConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldContext(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldDecode(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *func([]byte, aper.DecodeState) (s28.ENBConfigurationUpdateAcknowledge, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldEncode(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *func(*s28.ENBConfigurationUpdateAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldInfo(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldInject(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *func(s28.ENBConfigurationUpdateAcknowledge) SuccessfulValue {
	return &v.inject
}
func BridgeENBConfigurationUpdateAcknowledgeSuccessfulBindingFieldValidate(v *ENBConfigurationUpdateAcknowledgeSuccessfulBinding) *func(*s28.ENBConfigurationUpdateAcknowledge, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
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
func BridgeERABModificationConfirmSuccessfulBindingFieldCapture(v *ERABModificationConfirmSuccessfulBinding) *func(s49.ERABModificationConfirm, aper.DecodeState) (s49.ERABModificationConfirm, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModificationConfirmSuccessfulBindingFieldCompare(v *ERABModificationConfirmSuccessfulBinding) *func(s49.ERABModificationConfirm, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModificationConfirmSuccessfulBindingFieldContext(v *ERABModificationConfirmSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModificationConfirmSuccessfulBindingFieldDecode(v *ERABModificationConfirmSuccessfulBinding) *func([]byte, aper.DecodeState) (s49.ERABModificationConfirm, error) {
	return &v.decode
}
func BridgeERABModificationConfirmSuccessfulBindingFieldEncode(v *ERABModificationConfirmSuccessfulBinding) *func(*s49.ERABModificationConfirm, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModificationConfirmSuccessfulBindingFieldInfo(v *ERABModificationConfirmSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeERABModificationConfirmSuccessfulBindingFieldInject(v *ERABModificationConfirmSuccessfulBinding) *func(s49.ERABModificationConfirm) SuccessfulValue {
	return &v.inject
}
func BridgeERABModificationConfirmSuccessfulBindingFieldValidate(v *ERABModificationConfirmSuccessfulBinding) *func(*s49.ERABModificationConfirm, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeERABModifyResponseSuccessfulBindingFieldCapture(v *ERABModifyResponseSuccessfulBinding) *func(s57.ERABModifyResponse, aper.DecodeState) (s57.ERABModifyResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeERABModifyResponseSuccessfulBindingFieldCompare(v *ERABModifyResponseSuccessfulBinding) *func(s57.ERABModifyResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABModifyResponseSuccessfulBindingFieldContext(v *ERABModifyResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABModifyResponseSuccessfulBindingFieldDecode(v *ERABModifyResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s57.ERABModifyResponse, error) {
	return &v.decode
}
func BridgeERABModifyResponseSuccessfulBindingFieldEncode(v *ERABModifyResponseSuccessfulBinding) *func(*s57.ERABModifyResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABModifyResponseSuccessfulBindingFieldInfo(v *ERABModifyResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeERABModifyResponseSuccessfulBindingFieldInject(v *ERABModifyResponseSuccessfulBinding) *func(s57.ERABModifyResponse) SuccessfulValue {
	return &v.inject
}
func BridgeERABModifyResponseSuccessfulBindingFieldValidate(v *ERABModifyResponseSuccessfulBinding) *func(*s57.ERABModifyResponse, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeERABReleaseResponseSuccessfulBindingFieldCapture(v *ERABReleaseResponseSuccessfulBinding) *func(s57.ERABReleaseResponse, aper.DecodeState) (s57.ERABReleaseResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeERABReleaseResponseSuccessfulBindingFieldCompare(v *ERABReleaseResponseSuccessfulBinding) *func(s57.ERABReleaseResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABReleaseResponseSuccessfulBindingFieldContext(v *ERABReleaseResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABReleaseResponseSuccessfulBindingFieldDecode(v *ERABReleaseResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s57.ERABReleaseResponse, error) {
	return &v.decode
}
func BridgeERABReleaseResponseSuccessfulBindingFieldEncode(v *ERABReleaseResponseSuccessfulBinding) *func(*s57.ERABReleaseResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABReleaseResponseSuccessfulBindingFieldInfo(v *ERABReleaseResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeERABReleaseResponseSuccessfulBindingFieldInject(v *ERABReleaseResponseSuccessfulBinding) *func(s57.ERABReleaseResponse) SuccessfulValue {
	return &v.inject
}
func BridgeERABReleaseResponseSuccessfulBindingFieldValidate(v *ERABReleaseResponseSuccessfulBinding) *func(*s57.ERABReleaseResponse, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeERABSetupResponseSuccessfulBindingFieldCapture(v *ERABSetupResponseSuccessfulBinding) *func(s57.ERABSetupResponse, aper.DecodeState) (s57.ERABSetupResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeERABSetupResponseSuccessfulBindingFieldCompare(v *ERABSetupResponseSuccessfulBinding) *func(s57.ERABSetupResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeERABSetupResponseSuccessfulBindingFieldContext(v *ERABSetupResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeERABSetupResponseSuccessfulBindingFieldDecode(v *ERABSetupResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s57.ERABSetupResponse, error) {
	return &v.decode
}
func BridgeERABSetupResponseSuccessfulBindingFieldEncode(v *ERABSetupResponseSuccessfulBinding) *func(*s57.ERABSetupResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeERABSetupResponseSuccessfulBindingFieldInfo(v *ERABSetupResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeERABSetupResponseSuccessfulBindingFieldInject(v *ERABSetupResponseSuccessfulBinding) *func(s57.ERABSetupResponse) SuccessfulValue {
	return &v.inject
}
func BridgeERABSetupResponseSuccessfulBindingFieldValidate(v *ERABSetupResponseSuccessfulBinding) *func(*s57.ERABSetupResponse, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldCapture(v *HandoverCancelAcknowledgeSuccessfulBinding) *func(s29.HandoverCancelAcknowledge, aper.DecodeState) (s29.HandoverCancelAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldCompare(v *HandoverCancelAcknowledgeSuccessfulBinding) *func(s29.HandoverCancelAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldContext(v *HandoverCancelAcknowledgeSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldDecode(v *HandoverCancelAcknowledgeSuccessfulBinding) *func([]byte, aper.DecodeState) (s29.HandoverCancelAcknowledge, error) {
	return &v.decode
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldEncode(v *HandoverCancelAcknowledgeSuccessfulBinding) *func(*s29.HandoverCancelAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldInfo(v *HandoverCancelAcknowledgeSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldInject(v *HandoverCancelAcknowledgeSuccessfulBinding) *func(s29.HandoverCancelAcknowledge) SuccessfulValue {
	return &v.inject
}
func BridgeHandoverCancelAcknowledgeSuccessfulBindingFieldValidate(v *HandoverCancelAcknowledgeSuccessfulBinding) *func(*s29.HandoverCancelAcknowledge, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeHandoverCommandSuccessfulBindingFieldCapture(v *HandoverCommandSuccessfulBinding) *func(s50.HandoverCommand, aper.DecodeState) (s50.HandoverCommand, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverCommandSuccessfulBindingFieldCompare(v *HandoverCommandSuccessfulBinding) *func(s50.HandoverCommand, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverCommandSuccessfulBindingFieldContext(v *HandoverCommandSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverCommandSuccessfulBindingFieldDecode(v *HandoverCommandSuccessfulBinding) *func([]byte, aper.DecodeState) (s50.HandoverCommand, error) {
	return &v.decode
}
func BridgeHandoverCommandSuccessfulBindingFieldEncode(v *HandoverCommandSuccessfulBinding) *func(*s50.HandoverCommand, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverCommandSuccessfulBindingFieldInfo(v *HandoverCommandSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeHandoverCommandSuccessfulBindingFieldInject(v *HandoverCommandSuccessfulBinding) *func(s50.HandoverCommand) SuccessfulValue {
	return &v.inject
}
func BridgeHandoverCommandSuccessfulBindingFieldValidate(v *HandoverCommandSuccessfulBinding) *func(*s50.HandoverCommand, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldCapture(v *HandoverRequestAcknowledgeSuccessfulBinding) *func(s49.HandoverRequestAcknowledge, aper.DecodeState) (s49.HandoverRequestAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldCompare(v *HandoverRequestAcknowledgeSuccessfulBinding) *func(s49.HandoverRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldContext(v *HandoverRequestAcknowledgeSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldDecode(v *HandoverRequestAcknowledgeSuccessfulBinding) *func([]byte, aper.DecodeState) (s49.HandoverRequestAcknowledge, error) {
	return &v.decode
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldEncode(v *HandoverRequestAcknowledgeSuccessfulBinding) *func(*s49.HandoverRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldInfo(v *HandoverRequestAcknowledgeSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldInject(v *HandoverRequestAcknowledgeSuccessfulBinding) *func(s49.HandoverRequestAcknowledge) SuccessfulValue {
	return &v.inject
}
func BridgeHandoverRequestAcknowledgeSuccessfulBindingFieldValidate(v *HandoverRequestAcknowledgeSuccessfulBinding) *func(*s49.HandoverRequestAcknowledge, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldCapture(v *InitialContextSetupResponseSuccessfulBinding) *func(s50.InitialContextSetupResponse, aper.DecodeState) (s50.InitialContextSetupResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldCompare(v *InitialContextSetupResponseSuccessfulBinding) *func(s50.InitialContextSetupResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldContext(v *InitialContextSetupResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldDecode(v *InitialContextSetupResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s50.InitialContextSetupResponse, error) {
	return &v.decode
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldEncode(v *InitialContextSetupResponseSuccessfulBinding) *func(*s50.InitialContextSetupResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldInfo(v *InitialContextSetupResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldInject(v *InitialContextSetupResponseSuccessfulBinding) *func(s50.InitialContextSetupResponse) SuccessfulValue {
	return &v.inject
}
func BridgeInitialContextSetupResponseSuccessfulBindingFieldValidate(v *InitialContextSetupResponseSuccessfulBinding) *func(*s50.InitialContextSetupResponse, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeKillResponseSuccessfulBindingFieldCapture(v *KillResponseSuccessfulBinding) *func(s42.KillResponse, aper.DecodeState) (s42.KillResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeKillResponseSuccessfulBindingFieldCompare(v *KillResponseSuccessfulBinding) *func(s42.KillResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillResponseSuccessfulBindingFieldContext(v *KillResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillResponseSuccessfulBindingFieldDecode(v *KillResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s42.KillResponse, error) {
	return &v.decode
}
func BridgeKillResponseSuccessfulBindingFieldEncode(v *KillResponseSuccessfulBinding) *func(*s42.KillResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillResponseSuccessfulBindingFieldInfo(v *KillResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeKillResponseSuccessfulBindingFieldInject(v *KillResponseSuccessfulBinding) *func(s42.KillResponse) SuccessfulValue {
	return &v.inject
}
func BridgeKillResponseSuccessfulBindingFieldValidate(v *KillResponseSuccessfulBinding) *func(*s42.KillResponse, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeMMEConfigurationTransferENDCSONConfigurationTransferIEBindingFieldCodec(v *MMEConfigurationTransferENDCSONConfigurationTransferIEBinding) *ENDCSONConfigurationTransferValueCodec {
	return &v.codec
}
func BridgeMMEConfigurationTransferENDCSONConfigurationTransferIEBindingFieldGet(v *MMEConfigurationTransferENDCSONConfigurationTransferIEBinding) *func(*MMEConfigurationTransferIEValue) (*ENDCSONConfigurationTransfer, bool) {
	return &v.get
}
func BridgeMMEConfigurationTransferENDCSONConfigurationTransferIEBindingFieldInfo(v *MMEConfigurationTransferENDCSONConfigurationTransferIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEConfigurationTransferENDCSONConfigurationTransferIEBindingFieldInject(v *MMEConfigurationTransferENDCSONConfigurationTransferIEBinding) *func(ENDCSONConfigurationTransfer) MMEConfigurationTransferIEValue {
	return &v.inject
}
func BridgeMMEConfigurationTransferIEContainerValueCodecFieldCapture(v *MMEConfigurationTransferIEContainerValueCodec) *func(MMEConfigurationTransferIEContainer, aper.DecodeState) (MMEConfigurationTransferIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationTransferIEContainerValueCodecFieldCompare(v *MMEConfigurationTransferIEContainerValueCodec) *func(MMEConfigurationTransferIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationTransferIEContainerValueCodecFieldContext(v *MMEConfigurationTransferIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationTransferIEContainerValueCodecFieldDecode(v *MMEConfigurationTransferIEContainerValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationTransferIEContainer, error) {
	return &v.decode
}
func BridgeMMEConfigurationTransferIEContainerValueCodecFieldEncode(v *MMEConfigurationTransferIEContainerValueCodec) *func(MMEConfigurationTransferIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationTransferIEContainerValueCodecFieldPath(v *MMEConfigurationTransferIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationTransferIEFieldFieldReplay(v *MMEConfigurationTransferIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeMMEConfigurationTransferIEFieldFieldWithoutReplay(v *MMEConfigurationTransferIEField) *bool {
	return &v.withoutReplay
}
func BridgeMMEConfigurationTransferIEFieldMethodMarshalAPERTo(v *MMEConfigurationTransferIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMMEConfigurationTransferIEFieldMethodUnmarshalAPERFrom(v *MMEConfigurationTransferIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMMEConfigurationTransferIEFieldValueCodecFieldCapture(v *MMEConfigurationTransferIEFieldValueCodec) *func(MMEConfigurationTransferIEField, aper.DecodeState) (MMEConfigurationTransferIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationTransferIEFieldValueCodecFieldCompare(v *MMEConfigurationTransferIEFieldValueCodec) *func(MMEConfigurationTransferIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationTransferIEFieldValueCodecFieldContext(v *MMEConfigurationTransferIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationTransferIEFieldValueCodecFieldDecode(v *MMEConfigurationTransferIEFieldValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationTransferIEField, error) {
	return &v.decode
}
func BridgeMMEConfigurationTransferIEFieldValueCodecFieldEncode(v *MMEConfigurationTransferIEFieldValueCodec) *func(MMEConfigurationTransferIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationTransferIEFieldValueCodecFieldPath(v *MMEConfigurationTransferIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldCapture(v *MMEConfigurationTransferIEValueERABIEContainerListValueCodec) *func(MMEConfigurationTransferIEValueERABIEContainerList, aper.DecodeState) (MMEConfigurationTransferIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldCompare(v *MMEConfigurationTransferIEValueERABIEContainerListValueCodec) *func(MMEConfigurationTransferIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldContext(v *MMEConfigurationTransferIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldDecode(v *MMEConfigurationTransferIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationTransferIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldEncode(v *MMEConfigurationTransferIEValueERABIEContainerListValueCodec) *func(MMEConfigurationTransferIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationTransferIEValueERABIEContainerListValueCodecFieldPath(v *MMEConfigurationTransferIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationTransferIEValueFieldId(v *MMEConfigurationTransferIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMMEConfigurationTransferIEValueFieldIsOpaque(v *MMEConfigurationTransferIEValue) *bool {
	return &v.isOpaque
}
func BridgeMMEConfigurationTransferIEValueFieldOpaque(v *MMEConfigurationTransferIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMMEConfigurationTransferIEValueFieldRowENDCSONConfigurationTransferMCT(v *MMEConfigurationTransferIEValue) **ENDCSONConfigurationTransfer {
	return &v.rowENDCSONConfigurationTransferMCT
}
func BridgeMMEConfigurationTransferIEValueFieldRowIntersystemSONConfigurationTransferMCT(v *MMEConfigurationTransferIEValue) **s00.IntersystemSONConfigurationTransfer {
	return &v.rowIntersystemSONConfigurationTransferMCT
}
func BridgeMMEConfigurationTransferIEValueFieldRowSONConfigurationTransferMCT(v *MMEConfigurationTransferIEValue) **SONConfigurationTransfer {
	return &v.rowSONConfigurationTransferMCT
}
func BridgeMMEConfigurationTransferIEValueMethodCaptureSemantics(v MMEConfigurationTransferIEValue, a0 aper.SemanticCapture) MMEConfigurationTransferIEValue {
	return v.captureSemantics(a0)
}
func BridgeMMEConfigurationTransferIEValueMethodCompareSemantics(v MMEConfigurationTransferIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMMEConfigurationTransferIEValueMethodDecode(v MMEConfigurationTransferIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (MMEConfigurationTransferIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeMMEConfigurationTransferIEValueMethodEncodeFresh(v MMEConfigurationTransferIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeMMEConfigurationTransferIEValueMethodMatchesID(v MMEConfigurationTransferIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeMMEConfigurationTransferIEValueMethodRule(v MMEConfigurationTransferIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEConfigurationTransferIEValueProtocolErrorIEContainerList, aper.DecodeState) (MMEConfigurationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEConfigurationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationTransferIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) *func(MMEConfigurationTransferIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *MMEConfigurationTransferIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldCapture(v *MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec) *func(MMEConfigurationTransferIEValueProtocolIEContainerList, aper.DecodeState) (MMEConfigurationTransferIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldCompare(v *MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec) *func(MMEConfigurationTransferIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldContext(v *MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldDecode(v *MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (MMEConfigurationTransferIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldEncode(v *MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec) *func(MMEConfigurationTransferIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationTransferIEValueProtocolIEContainerListValueCodecFieldPath(v *MMEConfigurationTransferIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldCodec(v *MMEConfigurationTransferIntersystemSONConfigurationTransferIEBinding) *s01.IntersystemSONConfigurationTransferValueCodec {
	return &v.codec
}
func BridgeMMEConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldGet(v *MMEConfigurationTransferIntersystemSONConfigurationTransferIEBinding) *func(*MMEConfigurationTransferIEValue) (*s00.IntersystemSONConfigurationTransfer, bool) {
	return &v.get
}
func BridgeMMEConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldInfo(v *MMEConfigurationTransferIntersystemSONConfigurationTransferIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMMEConfigurationTransferIntersystemSONConfigurationTransferIEBindingFieldInject(v *MMEConfigurationTransferIntersystemSONConfigurationTransferIEBinding) *func(s00.IntersystemSONConfigurationTransfer) MMEConfigurationTransferIEValue {
	return &v.inject
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldCapture(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *func(s30.MMEConfigurationUpdateAcknowledge, aper.DecodeState) (s30.MMEConfigurationUpdateAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldCompare(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *func(s30.MMEConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldContext(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldDecode(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *func([]byte, aper.DecodeState) (s30.MMEConfigurationUpdateAcknowledge, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldEncode(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *func(*s30.MMEConfigurationUpdateAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldInfo(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldInject(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *func(s30.MMEConfigurationUpdateAcknowledge) SuccessfulValue {
	return &v.inject
}
func BridgeMMEConfigurationUpdateAcknowledgeSuccessfulBindingFieldValidate(v *MMEConfigurationUpdateAcknowledgeSuccessfulBinding) *func(*s30.MMEConfigurationUpdateAcknowledge, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldCapture(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func(s58.PathSwitchRequestAcknowledge, aper.DecodeState) (s58.PathSwitchRequestAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldCompare(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func(s58.PathSwitchRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldContext(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldDecode(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func([]byte, aper.DecodeState) (s58.PathSwitchRequestAcknowledge, error) {
	return &v.decode
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldEncode(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func(*s58.PathSwitchRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldInfo(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldInject(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func(s58.PathSwitchRequestAcknowledge) SuccessfulValue {
	return &v.inject
}
func BridgePathSwitchRequestAcknowledgeSuccessfulBindingFieldValidate(v *PathSwitchRequestAcknowledgeSuccessfulBinding) *func(*s58.PathSwitchRequestAcknowledge, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeResetAcknowledgeSuccessfulBindingFieldCapture(v *ResetAcknowledgeSuccessfulBinding) *func(s55.ResetAcknowledge, aper.DecodeState) (s55.ResetAcknowledge, aper.Snapshot) {
	return &v.capture
}
func BridgeResetAcknowledgeSuccessfulBindingFieldCompare(v *ResetAcknowledgeSuccessfulBinding) *func(s55.ResetAcknowledge, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetAcknowledgeSuccessfulBindingFieldContext(v *ResetAcknowledgeSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAcknowledgeSuccessfulBindingFieldDecode(v *ResetAcknowledgeSuccessfulBinding) *func([]byte, aper.DecodeState) (s55.ResetAcknowledge, error) {
	return &v.decode
}
func BridgeResetAcknowledgeSuccessfulBindingFieldEncode(v *ResetAcknowledgeSuccessfulBinding) *func(*s55.ResetAcknowledge, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetAcknowledgeSuccessfulBindingFieldInfo(v *ResetAcknowledgeSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeResetAcknowledgeSuccessfulBindingFieldInject(v *ResetAcknowledgeSuccessfulBinding) *func(s55.ResetAcknowledge) SuccessfulValue {
	return &v.inject
}
func BridgeResetAcknowledgeSuccessfulBindingFieldValidate(v *ResetAcknowledgeSuccessfulBinding) *func(*s55.ResetAcknowledge, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeS1RemovalResponseSuccessfulBindingFieldCapture(v *S1RemovalResponseSuccessfulBinding) *func(s31.S1RemovalResponse, aper.DecodeState) (s31.S1RemovalResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalResponseSuccessfulBindingFieldCompare(v *S1RemovalResponseSuccessfulBinding) *func(s31.S1RemovalResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalResponseSuccessfulBindingFieldContext(v *S1RemovalResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalResponseSuccessfulBindingFieldDecode(v *S1RemovalResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s31.S1RemovalResponse, error) {
	return &v.decode
}
func BridgeS1RemovalResponseSuccessfulBindingFieldEncode(v *S1RemovalResponseSuccessfulBinding) *func(*s31.S1RemovalResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalResponseSuccessfulBindingFieldInfo(v *S1RemovalResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1RemovalResponseSuccessfulBindingFieldInject(v *S1RemovalResponseSuccessfulBinding) *func(s31.S1RemovalResponse) SuccessfulValue {
	return &v.inject
}
func BridgeS1RemovalResponseSuccessfulBindingFieldValidate(v *S1RemovalResponseSuccessfulBinding) *func(*s31.S1RemovalResponse, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeS1SetupResponseSuccessfulBindingFieldCapture(v *S1SetupResponseSuccessfulBinding) *func(s54.S1SetupResponse, aper.DecodeState) (s54.S1SetupResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupResponseSuccessfulBindingFieldCompare(v *S1SetupResponseSuccessfulBinding) *func(s54.S1SetupResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupResponseSuccessfulBindingFieldContext(v *S1SetupResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupResponseSuccessfulBindingFieldDecode(v *S1SetupResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s54.S1SetupResponse, error) {
	return &v.decode
}
func BridgeS1SetupResponseSuccessfulBindingFieldEncode(v *S1SetupResponseSuccessfulBinding) *func(*s54.S1SetupResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupResponseSuccessfulBindingFieldInfo(v *S1SetupResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1SetupResponseSuccessfulBindingFieldInject(v *S1SetupResponseSuccessfulBinding) *func(s54.S1SetupResponse) SuccessfulValue {
	return &v.inject
}
func BridgeS1SetupResponseSuccessfulBindingFieldValidate(v *S1SetupResponseSuccessfulBinding) *func(*s54.S1SetupResponse, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
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
func BridgeSONConfigurationTransferExtIEsValueFieldRowRequestedTNLInfo(v *SONConfigurationTransferExtIEsValue) **s31.RequestedTNLInfo {
	return &v.rowRequestedTNLInfo
}
func BridgeSONConfigurationTransferExtIEsValueFieldRowSynchronisationInformation(v *SONConfigurationTransferExtIEsValue) **s40.SynchronisationInformation {
	return &v.rowSynchronisationInformation
}
func BridgeSONConfigurationTransferExtIEsValueFieldRowX2TNLConfigurationInfo(v *SONConfigurationTransferExtIEsValue) **X2TNLConfigurationInfo {
	return &v.rowX2TNLConfigurationInfo
}
func BridgeSONConfigurationTransferExtIEsValueMethodMatchesID(v SONConfigurationTransferExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeSONConfigurationTransferExtIEsValueMethodRule(v SONConfigurationTransferExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeSONConfigurationTransferValueCodecFieldCapture(v *SONConfigurationTransferValueCodec) *func(SONConfigurationTransfer, aper.DecodeState) (SONConfigurationTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeSONConfigurationTransferValueCodecFieldCompare(v *SONConfigurationTransferValueCodec) *func(SONConfigurationTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONConfigurationTransferValueCodecFieldContext(v *SONConfigurationTransferValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONConfigurationTransferValueCodecFieldDecode(v *SONConfigurationTransferValueCodec) *func([]byte, aper.DecodeState) (SONConfigurationTransfer, error) {
	return &v.decode
}
func BridgeSONConfigurationTransferValueCodecFieldEncode(v *SONConfigurationTransferValueCodec) *func(SONConfigurationTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONConfigurationTransferValueCodecFieldPath(v *SONConfigurationTransferValueCodec) *aper.Path {
	return &v.path
}
func BridgeSuccessfulOutcomeMethodMarshalAPERTo(v *SuccessfulOutcome, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSuccessfulOutcomeMethodUnmarshalAPERFrom(v *SuccessfulOutcome, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSuccessfulValueFieldBodyENBConfigurationUpdateAcknowledge(v *SuccessfulValue) **s28.ENBConfigurationUpdateAcknowledge {
	return &v.bodyENBConfigurationUpdateAcknowledge
}
func BridgeSuccessfulValueFieldBodyERABModificationConfirm(v *SuccessfulValue) **s49.ERABModificationConfirm {
	return &v.bodyERABModificationConfirm
}
func BridgeSuccessfulValueFieldBodyERABModifyResponse(v *SuccessfulValue) **s57.ERABModifyResponse {
	return &v.bodyERABModifyResponse
}
func BridgeSuccessfulValueFieldBodyERABReleaseResponse(v *SuccessfulValue) **s57.ERABReleaseResponse {
	return &v.bodyERABReleaseResponse
}
func BridgeSuccessfulValueFieldBodyERABSetupResponse(v *SuccessfulValue) **s57.ERABSetupResponse {
	return &v.bodyERABSetupResponse
}
func BridgeSuccessfulValueFieldBodyHandoverCancelAcknowledge(v *SuccessfulValue) **s29.HandoverCancelAcknowledge {
	return &v.bodyHandoverCancelAcknowledge
}
func BridgeSuccessfulValueFieldBodyHandoverCommand(v *SuccessfulValue) **s50.HandoverCommand {
	return &v.bodyHandoverCommand
}
func BridgeSuccessfulValueFieldBodyHandoverRequestAcknowledge(v *SuccessfulValue) **s49.HandoverRequestAcknowledge {
	return &v.bodyHandoverRequestAcknowledge
}
func BridgeSuccessfulValueFieldBodyInitialContextSetupResponse(v *SuccessfulValue) **s50.InitialContextSetupResponse {
	return &v.bodyInitialContextSetupResponse
}
func BridgeSuccessfulValueFieldBodyKillResponse(v *SuccessfulValue) **s42.KillResponse {
	return &v.bodyKillResponse
}
func BridgeSuccessfulValueFieldBodyMMEConfigurationUpdateAcknowledge(v *SuccessfulValue) **s30.MMEConfigurationUpdateAcknowledge {
	return &v.bodyMMEConfigurationUpdateAcknowledge
}
func BridgeSuccessfulValueFieldBodyPathSwitchRequestAcknowledge(v *SuccessfulValue) **s58.PathSwitchRequestAcknowledge {
	return &v.bodyPathSwitchRequestAcknowledge
}
func BridgeSuccessfulValueFieldBodyResetAcknowledge(v *SuccessfulValue) **s55.ResetAcknowledge {
	return &v.bodyResetAcknowledge
}
func BridgeSuccessfulValueFieldBodyS1RemovalResponse(v *SuccessfulValue) **s31.S1RemovalResponse {
	return &v.bodyS1RemovalResponse
}
func BridgeSuccessfulValueFieldBodyS1SetupResponse(v *SuccessfulValue) **s54.S1SetupResponse {
	return &v.bodyS1SetupResponse
}
func BridgeSuccessfulValueFieldBodyUEContextModificationConfirm(v *SuccessfulValue) **s45.UEContextModificationConfirm {
	return &v.bodyUEContextModificationConfirm
}
func BridgeSuccessfulValueFieldBodyUEContextModificationResponse(v *SuccessfulValue) **s46.UEContextModificationResponse {
	return &v.bodyUEContextModificationResponse
}
func BridgeSuccessfulValueFieldBodyUEContextReleaseComplete(v *SuccessfulValue) **s57.UEContextReleaseComplete {
	return &v.bodyUEContextReleaseComplete
}
func BridgeSuccessfulValueFieldBodyUEContextResumeResponse(v *SuccessfulValue) **s49.UEContextResumeResponse {
	return &v.bodyUEContextResumeResponse
}
func BridgeSuccessfulValueFieldBodyUEContextSuspendResponse(v *SuccessfulValue) **s46.UEContextSuspendResponse {
	return &v.bodyUEContextSuspendResponse
}
func BridgeSuccessfulValueFieldBodyUERadioCapabilityIDMappingResponse(v *SuccessfulValue) **s46.UERadioCapabilityIDMappingResponse {
	return &v.bodyUERadioCapabilityIDMappingResponse
}
func BridgeSuccessfulValueFieldBodyUERadioCapabilityMatchResponse(v *SuccessfulValue) **s46.UERadioCapabilityMatchResponse {
	return &v.bodyUERadioCapabilityMatchResponse
}
func BridgeSuccessfulValueFieldBodyWriteReplaceWarningResponse(v *SuccessfulValue) **WriteReplaceWarningResponse {
	return &v.bodyWriteReplaceWarningResponse
}
func BridgeSuccessfulValueFieldCode(v *SuccessfulValue) *s00.ProcedureCode     { return &v.code }
func BridgeSuccessfulValueFieldIsOpaque(v *SuccessfulValue) *bool              { return &v.isOpaque }
func BridgeSuccessfulValueFieldOpaque(v *SuccessfulValue) *aper.OpaqueOpenType { return &v.opaque }
func BridgeUEContextModificationConfirmSuccessfulBindingFieldCapture(v *UEContextModificationConfirmSuccessfulBinding) *func(s45.UEContextModificationConfirm, aper.DecodeState) (s45.UEContextModificationConfirm, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationConfirmSuccessfulBindingFieldCompare(v *UEContextModificationConfirmSuccessfulBinding) *func(s45.UEContextModificationConfirm, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationConfirmSuccessfulBindingFieldContext(v *UEContextModificationConfirmSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmSuccessfulBindingFieldDecode(v *UEContextModificationConfirmSuccessfulBinding) *func([]byte, aper.DecodeState) (s45.UEContextModificationConfirm, error) {
	return &v.decode
}
func BridgeUEContextModificationConfirmSuccessfulBindingFieldEncode(v *UEContextModificationConfirmSuccessfulBinding) *func(*s45.UEContextModificationConfirm, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationConfirmSuccessfulBindingFieldInfo(v *UEContextModificationConfirmSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextModificationConfirmSuccessfulBindingFieldInject(v *UEContextModificationConfirmSuccessfulBinding) *func(s45.UEContextModificationConfirm) SuccessfulValue {
	return &v.inject
}
func BridgeUEContextModificationConfirmSuccessfulBindingFieldValidate(v *UEContextModificationConfirmSuccessfulBinding) *func(*s45.UEContextModificationConfirm, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldCapture(v *UEContextModificationResponseSuccessfulBinding) *func(s46.UEContextModificationResponse, aper.DecodeState) (s46.UEContextModificationResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldCompare(v *UEContextModificationResponseSuccessfulBinding) *func(s46.UEContextModificationResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldContext(v *UEContextModificationResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldDecode(v *UEContextModificationResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s46.UEContextModificationResponse, error) {
	return &v.decode
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldEncode(v *UEContextModificationResponseSuccessfulBinding) *func(*s46.UEContextModificationResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldInfo(v *UEContextModificationResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldInject(v *UEContextModificationResponseSuccessfulBinding) *func(s46.UEContextModificationResponse) SuccessfulValue {
	return &v.inject
}
func BridgeUEContextModificationResponseSuccessfulBindingFieldValidate(v *UEContextModificationResponseSuccessfulBinding) *func(*s46.UEContextModificationResponse, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldCapture(v *UEContextReleaseCompleteSuccessfulBinding) *func(s57.UEContextReleaseComplete, aper.DecodeState) (s57.UEContextReleaseComplete, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldCompare(v *UEContextReleaseCompleteSuccessfulBinding) *func(s57.UEContextReleaseComplete, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldContext(v *UEContextReleaseCompleteSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldDecode(v *UEContextReleaseCompleteSuccessfulBinding) *func([]byte, aper.DecodeState) (s57.UEContextReleaseComplete, error) {
	return &v.decode
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldEncode(v *UEContextReleaseCompleteSuccessfulBinding) *func(*s57.UEContextReleaseComplete, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldInfo(v *UEContextReleaseCompleteSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldInject(v *UEContextReleaseCompleteSuccessfulBinding) *func(s57.UEContextReleaseComplete) SuccessfulValue {
	return &v.inject
}
func BridgeUEContextReleaseCompleteSuccessfulBindingFieldValidate(v *UEContextReleaseCompleteSuccessfulBinding) *func(*s57.UEContextReleaseComplete, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldCapture(v *UEContextResumeResponseSuccessfulBinding) *func(s49.UEContextResumeResponse, aper.DecodeState) (s49.UEContextResumeResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldCompare(v *UEContextResumeResponseSuccessfulBinding) *func(s49.UEContextResumeResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldContext(v *UEContextResumeResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldDecode(v *UEContextResumeResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s49.UEContextResumeResponse, error) {
	return &v.decode
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldEncode(v *UEContextResumeResponseSuccessfulBinding) *func(*s49.UEContextResumeResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldInfo(v *UEContextResumeResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldInject(v *UEContextResumeResponseSuccessfulBinding) *func(s49.UEContextResumeResponse) SuccessfulValue {
	return &v.inject
}
func BridgeUEContextResumeResponseSuccessfulBindingFieldValidate(v *UEContextResumeResponseSuccessfulBinding) *func(*s49.UEContextResumeResponse, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldCapture(v *UEContextSuspendResponseSuccessfulBinding) *func(s46.UEContextSuspendResponse, aper.DecodeState) (s46.UEContextSuspendResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldCompare(v *UEContextSuspendResponseSuccessfulBinding) *func(s46.UEContextSuspendResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldContext(v *UEContextSuspendResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldDecode(v *UEContextSuspendResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s46.UEContextSuspendResponse, error) {
	return &v.decode
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldEncode(v *UEContextSuspendResponseSuccessfulBinding) *func(*s46.UEContextSuspendResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldInfo(v *UEContextSuspendResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldInject(v *UEContextSuspendResponseSuccessfulBinding) *func(s46.UEContextSuspendResponse) SuccessfulValue {
	return &v.inject
}
func BridgeUEContextSuspendResponseSuccessfulBindingFieldValidate(v *UEContextSuspendResponseSuccessfulBinding) *func(*s46.UEContextSuspendResponse, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldCapture(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func(s46.UERadioCapabilityIDMappingResponse, aper.DecodeState) (s46.UERadioCapabilityIDMappingResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldCompare(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func(s46.UERadioCapabilityIDMappingResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldContext(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldDecode(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s46.UERadioCapabilityIDMappingResponse, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldEncode(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func(*s46.UERadioCapabilityIDMappingResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldInfo(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldInject(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func(s46.UERadioCapabilityIDMappingResponse) SuccessfulValue {
	return &v.inject
}
func BridgeUERadioCapabilityIDMappingResponseSuccessfulBindingFieldValidate(v *UERadioCapabilityIDMappingResponseSuccessfulBinding) *func(*s46.UERadioCapabilityIDMappingResponse, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldCapture(v *UERadioCapabilityMatchResponseSuccessfulBinding) *func(s46.UERadioCapabilityMatchResponse, aper.DecodeState) (s46.UERadioCapabilityMatchResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldCompare(v *UERadioCapabilityMatchResponseSuccessfulBinding) *func(s46.UERadioCapabilityMatchResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldContext(v *UERadioCapabilityMatchResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldDecode(v *UERadioCapabilityMatchResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s46.UERadioCapabilityMatchResponse, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldEncode(v *UERadioCapabilityMatchResponseSuccessfulBinding) *func(*s46.UERadioCapabilityMatchResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldInfo(v *UERadioCapabilityMatchResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldInject(v *UERadioCapabilityMatchResponseSuccessfulBinding) *func(s46.UERadioCapabilityMatchResponse) SuccessfulValue {
	return &v.inject
}
func BridgeUERadioCapabilityMatchResponseSuccessfulBindingFieldValidate(v *UERadioCapabilityMatchResponseSuccessfulBinding) *func(*s46.UERadioCapabilityMatchResponse, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeWriteReplaceWarningRequestFieldPerPadding(v *WriteReplaceWarningRequest) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeWriteReplaceWarningRequestMethodMarshalAPERBudget(v *WriteReplaceWarningRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWriteReplaceWarningRequestMethodUnmarshalAPERFrom(v *WriteReplaceWarningRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeWriteReplaceWarningResponseFieldReceived(v *WriteReplaceWarningResponse) *bool {
	return &v.received
}
func BridgeWriteReplaceWarningResponseFieldReceivedAbsolute(v *WriteReplaceWarningResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeWriteReplaceWarningResponseFieldReceivedBytes(v *WriteReplaceWarningResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeWriteReplaceWarningResponseMethodMarshalAPERBudget(v *WriteReplaceWarningResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
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
func BridgeWriteReplaceWarningResponseSuccessfulBindingFieldValidate(v *WriteReplaceWarningResponseSuccessfulBinding) *func(*WriteReplaceWarningResponse, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
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
func (v *MMEConfigurationTransferIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 130:
		if value, ok := v.AsSONConfigurationTransferMCT(); ok {
			return value, true
		}
	case 295:
		if value, ok := v.AsENDCSONConfigurationTransferMCT(); ok {
			return value, true
		}
	case 309:
		if value, ok := v.AsIntersystemSONConfigurationTransferMCT(); ok {
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
