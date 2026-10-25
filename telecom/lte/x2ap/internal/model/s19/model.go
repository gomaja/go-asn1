// Code generated from the locked X2AP source closure. DO NOT EDIT.

// Package s19 implements the x2ap root package.
package s19

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s08"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	s15 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s15"
	s16 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	runtime "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// HandoverRequestAcknowledgeSuccessfulBinding is the concrete SuccessfulBinding[HandoverRequestAcknowledge].
type HandoverRequestAcknowledgeSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(HandoverRequestAcknowledge, aper.DecodeState) (HandoverRequestAcknowledge, aper.Snapshot)
	compare  func(HandoverRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*HandoverRequestAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*HandoverRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (HandoverRequestAcknowledge, error)
	inject   func(HandoverRequestAcknowledge) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b HandoverRequestAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b HandoverRequestAcknowledgeSuccessfulBinding) Codec() HandoverRequestAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return HandoverRequestAcknowledgeValueCodec{}
	}
	return HandoverRequestAcknowledgeValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value HandoverRequestAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b HandoverRequestAcknowledgeSuccessfulBinding) Build(body HandoverRequestAcknowledge, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// X2SetupResponseSuccessfulBinding is the concrete SuccessfulBinding[X2SetupResponse].
type X2SetupResponseSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(X2SetupResponse, aper.DecodeState) (X2SetupResponse, aper.Snapshot)
	compare  func(X2SetupResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*X2SetupResponse, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*X2SetupResponse, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (X2SetupResponse, error)
	inject   func(X2SetupResponse) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b X2SetupResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b X2SetupResponseSuccessfulBinding) Codec() X2SetupResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return X2SetupResponseValueCodec{}
	}
	return X2SetupResponseValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value X2SetupResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b X2SetupResponseSuccessfulBinding) Build(body X2SetupResponse, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// ResetResponseSuccessfulBinding is the concrete SuccessfulBinding[ResetResponse].
type ResetResponseSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(ResetResponse, aper.DecodeState) (ResetResponse, aper.Snapshot)
	compare  func(ResetResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*ResetResponse, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*ResetResponse, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (ResetResponse, error)
	inject   func(ResetResponse) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b ResetResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b ResetResponseSuccessfulBinding) Codec() ResetResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ResetResponseValueCodec{}
	}
	return ResetResponseValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value ResetResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b ResetResponseSuccessfulBinding) Build(body ResetResponse, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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
	context  s00.X2apInternalCodecContext
	capture  func(ENBConfigurationUpdateAcknowledge, aper.DecodeState) (ENBConfigurationUpdateAcknowledge, aper.Snapshot)
	compare  func(ENBConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*ENBConfigurationUpdateAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*ENBConfigurationUpdateAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledge, error)
	inject   func(ENBConfigurationUpdateAcknowledge) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b ENBConfigurationUpdateAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b ENBConfigurationUpdateAcknowledgeSuccessfulBinding) Codec() ENBConfigurationUpdateAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ENBConfigurationUpdateAcknowledgeValueCodec{}
	}
	return ENBConfigurationUpdateAcknowledgeValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value ENBConfigurationUpdateAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b ENBConfigurationUpdateAcknowledgeSuccessfulBinding) Build(body ENBConfigurationUpdateAcknowledge, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// ResourceStatusResponseSuccessfulBinding is the concrete SuccessfulBinding[ResourceStatusResponse].
type ResourceStatusResponseSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(ResourceStatusResponse, aper.DecodeState) (ResourceStatusResponse, aper.Snapshot)
	compare  func(ResourceStatusResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*ResourceStatusResponse, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*ResourceStatusResponse, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (ResourceStatusResponse, error)
	inject   func(ResourceStatusResponse) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b ResourceStatusResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b ResourceStatusResponseSuccessfulBinding) Codec() ResourceStatusResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ResourceStatusResponseValueCodec{}
	}
	return ResourceStatusResponseValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value ResourceStatusResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b ResourceStatusResponseSuccessfulBinding) Build(body ResourceStatusResponse, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// MobilityChangeAcknowledgeSuccessfulBinding is the concrete SuccessfulBinding[MobilityChangeAcknowledge].
type MobilityChangeAcknowledgeSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(MobilityChangeAcknowledge, aper.DecodeState) (MobilityChangeAcknowledge, aper.Snapshot)
	compare  func(MobilityChangeAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*MobilityChangeAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*MobilityChangeAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (MobilityChangeAcknowledge, error)
	inject   func(MobilityChangeAcknowledge) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b MobilityChangeAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b MobilityChangeAcknowledgeSuccessfulBinding) Codec() MobilityChangeAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return MobilityChangeAcknowledgeValueCodec{}
	}
	return MobilityChangeAcknowledgeValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value MobilityChangeAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b MobilityChangeAcknowledgeSuccessfulBinding) Build(body MobilityChangeAcknowledge, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// CellActivationResponseSuccessfulBinding is the concrete SuccessfulBinding[CellActivationResponse].
type CellActivationResponseSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(CellActivationResponse, aper.DecodeState) (CellActivationResponse, aper.Snapshot)
	compare  func(CellActivationResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*CellActivationResponse, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*CellActivationResponse, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (CellActivationResponse, error)
	inject   func(CellActivationResponse) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b CellActivationResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b CellActivationResponseSuccessfulBinding) Codec() CellActivationResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return CellActivationResponseValueCodec{}
	}
	return CellActivationResponseValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value CellActivationResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b CellActivationResponseSuccessfulBinding) Build(body CellActivationResponse, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// X2RemovalResponseSuccessfulBinding is the concrete SuccessfulBinding[X2RemovalResponse].
type X2RemovalResponseSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(X2RemovalResponse, aper.DecodeState) (X2RemovalResponse, aper.Snapshot)
	compare  func(X2RemovalResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*X2RemovalResponse, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*X2RemovalResponse, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (X2RemovalResponse, error)
	inject   func(X2RemovalResponse) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b X2RemovalResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b X2RemovalResponseSuccessfulBinding) Codec() X2RemovalResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return X2RemovalResponseValueCodec{}
	}
	return X2RemovalResponseValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value X2RemovalResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b X2RemovalResponseSuccessfulBinding) Build(body X2RemovalResponse, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// SeNBAdditionRequestAcknowledgeSuccessfulBinding is the concrete SuccessfulBinding[SeNBAdditionRequestAcknowledge].
type SeNBAdditionRequestAcknowledgeSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(SeNBAdditionRequestAcknowledge, aper.DecodeState) (SeNBAdditionRequestAcknowledge, aper.Snapshot)
	compare  func(SeNBAdditionRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*SeNBAdditionRequestAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*SeNBAdditionRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (SeNBAdditionRequestAcknowledge, error)
	inject   func(SeNBAdditionRequestAcknowledge) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b SeNBAdditionRequestAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b SeNBAdditionRequestAcknowledgeSuccessfulBinding) Codec() SeNBAdditionRequestAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SeNBAdditionRequestAcknowledgeValueCodec{}
	}
	return SeNBAdditionRequestAcknowledgeValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value SeNBAdditionRequestAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b SeNBAdditionRequestAcknowledgeSuccessfulBinding) Build(body SeNBAdditionRequestAcknowledge, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// SeNBModificationRequestAcknowledgeSuccessfulBinding is the concrete SuccessfulBinding[SeNBModificationRequestAcknowledge].
type SeNBModificationRequestAcknowledgeSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(SeNBModificationRequestAcknowledge, aper.DecodeState) (SeNBModificationRequestAcknowledge, aper.Snapshot)
	compare  func(SeNBModificationRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*SeNBModificationRequestAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*SeNBModificationRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (SeNBModificationRequestAcknowledge, error)
	inject   func(SeNBModificationRequestAcknowledge) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b SeNBModificationRequestAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b SeNBModificationRequestAcknowledgeSuccessfulBinding) Codec() SeNBModificationRequestAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SeNBModificationRequestAcknowledgeValueCodec{}
	}
	return SeNBModificationRequestAcknowledgeValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value SeNBModificationRequestAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b SeNBModificationRequestAcknowledgeSuccessfulBinding) Build(body SeNBModificationRequestAcknowledge, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// SeNBModificationConfirmSuccessfulBinding is the concrete SuccessfulBinding[SeNBModificationConfirm].
type SeNBModificationConfirmSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(SeNBModificationConfirm, aper.DecodeState) (SeNBModificationConfirm, aper.Snapshot)
	compare  func(SeNBModificationConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*SeNBModificationConfirm, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*SeNBModificationConfirm, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (SeNBModificationConfirm, error)
	inject   func(SeNBModificationConfirm) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b SeNBModificationConfirmSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b SeNBModificationConfirmSuccessfulBinding) Codec() SeNBModificationConfirmValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SeNBModificationConfirmValueCodec{}
	}
	return SeNBModificationConfirmValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value SeNBModificationConfirm, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b SeNBModificationConfirmSuccessfulBinding) Build(body SeNBModificationConfirm, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// SeNBReleaseConfirmSuccessfulBinding is the concrete SuccessfulBinding[SeNBReleaseConfirm].
type SeNBReleaseConfirmSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(SeNBReleaseConfirm, aper.DecodeState) (SeNBReleaseConfirm, aper.Snapshot)
	compare  func(SeNBReleaseConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*SeNBReleaseConfirm, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*SeNBReleaseConfirm, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (SeNBReleaseConfirm, error)
	inject   func(SeNBReleaseConfirm) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b SeNBReleaseConfirmSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b SeNBReleaseConfirmSuccessfulBinding) Codec() SeNBReleaseConfirmValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SeNBReleaseConfirmValueCodec{}
	}
	return SeNBReleaseConfirmValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value SeNBReleaseConfirm, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b SeNBReleaseConfirmSuccessfulBinding) Build(body SeNBReleaseConfirm, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// RetrieveUEContextResponseSuccessfulBinding is the concrete SuccessfulBinding[RetrieveUEContextResponse].
type RetrieveUEContextResponseSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(RetrieveUEContextResponse, aper.DecodeState) (RetrieveUEContextResponse, aper.Snapshot)
	compare  func(RetrieveUEContextResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*RetrieveUEContextResponse, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*RetrieveUEContextResponse, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (RetrieveUEContextResponse, error)
	inject   func(RetrieveUEContextResponse) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b RetrieveUEContextResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b RetrieveUEContextResponseSuccessfulBinding) Codec() RetrieveUEContextResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return RetrieveUEContextResponseValueCodec{}
	}
	return RetrieveUEContextResponseValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value RetrieveUEContextResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b RetrieveUEContextResponseSuccessfulBinding) Build(body RetrieveUEContextResponse, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// SgNBAdditionRequestAcknowledgeSuccessfulBinding is the concrete SuccessfulBinding[SgNBAdditionRequestAcknowledge].
type SgNBAdditionRequestAcknowledgeSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(SgNBAdditionRequestAcknowledge, aper.DecodeState) (SgNBAdditionRequestAcknowledge, aper.Snapshot)
	compare  func(SgNBAdditionRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*SgNBAdditionRequestAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*SgNBAdditionRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (SgNBAdditionRequestAcknowledge, error)
	inject   func(SgNBAdditionRequestAcknowledge) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b SgNBAdditionRequestAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b SgNBAdditionRequestAcknowledgeSuccessfulBinding) Codec() SgNBAdditionRequestAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SgNBAdditionRequestAcknowledgeValueCodec{}
	}
	return SgNBAdditionRequestAcknowledgeValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value SgNBAdditionRequestAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b SgNBAdditionRequestAcknowledgeSuccessfulBinding) Build(body SgNBAdditionRequestAcknowledge, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// SgNBModificationRequestAcknowledgeSuccessfulBinding is the concrete SuccessfulBinding[SgNBModificationRequestAcknowledge].
type SgNBModificationRequestAcknowledgeSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(SgNBModificationRequestAcknowledge, aper.DecodeState) (SgNBModificationRequestAcknowledge, aper.Snapshot)
	compare  func(SgNBModificationRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*SgNBModificationRequestAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*SgNBModificationRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (SgNBModificationRequestAcknowledge, error)
	inject   func(SgNBModificationRequestAcknowledge) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b SgNBModificationRequestAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b SgNBModificationRequestAcknowledgeSuccessfulBinding) Codec() SgNBModificationRequestAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SgNBModificationRequestAcknowledgeValueCodec{}
	}
	return SgNBModificationRequestAcknowledgeValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value SgNBModificationRequestAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b SgNBModificationRequestAcknowledgeSuccessfulBinding) Build(body SgNBModificationRequestAcknowledge, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// SgNBModificationConfirmSuccessfulBinding is the concrete SuccessfulBinding[SgNBModificationConfirm].
type SgNBModificationConfirmSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(SgNBModificationConfirm, aper.DecodeState) (SgNBModificationConfirm, aper.Snapshot)
	compare  func(SgNBModificationConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*SgNBModificationConfirm, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*SgNBModificationConfirm, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (SgNBModificationConfirm, error)
	inject   func(SgNBModificationConfirm) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b SgNBModificationConfirmSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b SgNBModificationConfirmSuccessfulBinding) Codec() SgNBModificationConfirmValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SgNBModificationConfirmValueCodec{}
	}
	return SgNBModificationConfirmValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value SgNBModificationConfirm, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b SgNBModificationConfirmSuccessfulBinding) Build(body SgNBModificationConfirm, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// SgNBReleaseRequestAcknowledgeSuccessfulBinding is the concrete SuccessfulBinding[SgNBReleaseRequestAcknowledge].
type SgNBReleaseRequestAcknowledgeSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(SgNBReleaseRequestAcknowledge, aper.DecodeState) (SgNBReleaseRequestAcknowledge, aper.Snapshot)
	compare  func(SgNBReleaseRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*SgNBReleaseRequestAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*SgNBReleaseRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (SgNBReleaseRequestAcknowledge, error)
	inject   func(SgNBReleaseRequestAcknowledge) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b SgNBReleaseRequestAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b SgNBReleaseRequestAcknowledgeSuccessfulBinding) Codec() SgNBReleaseRequestAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SgNBReleaseRequestAcknowledgeValueCodec{}
	}
	return SgNBReleaseRequestAcknowledgeValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value SgNBReleaseRequestAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b SgNBReleaseRequestAcknowledgeSuccessfulBinding) Build(body SgNBReleaseRequestAcknowledge, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// SgNBReleaseConfirmSuccessfulBinding is the concrete SuccessfulBinding[SgNBReleaseConfirm].
type SgNBReleaseConfirmSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(SgNBReleaseConfirm, aper.DecodeState) (SgNBReleaseConfirm, aper.Snapshot)
	compare  func(SgNBReleaseConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*SgNBReleaseConfirm, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*SgNBReleaseConfirm, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (SgNBReleaseConfirm, error)
	inject   func(SgNBReleaseConfirm) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b SgNBReleaseConfirmSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b SgNBReleaseConfirmSuccessfulBinding) Codec() SgNBReleaseConfirmValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SgNBReleaseConfirmValueCodec{}
	}
	return SgNBReleaseConfirmValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value SgNBReleaseConfirm, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b SgNBReleaseConfirmSuccessfulBinding) Build(body SgNBReleaseConfirm, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// SgNBChangeConfirmSuccessfulBinding is the concrete SuccessfulBinding[SgNBChangeConfirm].
type SgNBChangeConfirmSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(SgNBChangeConfirm, aper.DecodeState) (SgNBChangeConfirm, aper.Snapshot)
	compare  func(SgNBChangeConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*SgNBChangeConfirm, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*SgNBChangeConfirm, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (SgNBChangeConfirm, error)
	inject   func(SgNBChangeConfirm) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b SgNBChangeConfirmSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b SgNBChangeConfirmSuccessfulBinding) Codec() SgNBChangeConfirmValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return SgNBChangeConfirmValueCodec{}
	}
	return SgNBChangeConfirmValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value SgNBChangeConfirm, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b SgNBChangeConfirmSuccessfulBinding) Build(body SgNBChangeConfirm, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// ENDCX2SetupResponseSuccessfulBinding is the concrete SuccessfulBinding[ENDCX2SetupResponse].
type ENDCX2SetupResponseSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(ENDCX2SetupResponse, aper.DecodeState) (ENDCX2SetupResponse, aper.Snapshot)
	compare  func(ENDCX2SetupResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*ENDCX2SetupResponse, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*ENDCX2SetupResponse, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (ENDCX2SetupResponse, error)
	inject   func(ENDCX2SetupResponse) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b ENDCX2SetupResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b ENDCX2SetupResponseSuccessfulBinding) Codec() ENDCX2SetupResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ENDCX2SetupResponseValueCodec{}
	}
	return ENDCX2SetupResponseValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value ENDCX2SetupResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b ENDCX2SetupResponseSuccessfulBinding) Build(body ENDCX2SetupResponse, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// ENDCConfigurationUpdateAcknowledgeSuccessfulBinding is the concrete SuccessfulBinding[ENDCConfigurationUpdateAcknowledge].
type ENDCConfigurationUpdateAcknowledgeSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(ENDCConfigurationUpdateAcknowledge, aper.DecodeState) (ENDCConfigurationUpdateAcknowledge, aper.Snapshot)
	compare  func(ENDCConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*ENDCConfigurationUpdateAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*ENDCConfigurationUpdateAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (ENDCConfigurationUpdateAcknowledge, error)
	inject   func(ENDCConfigurationUpdateAcknowledge) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b ENDCConfigurationUpdateAcknowledgeSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b ENDCConfigurationUpdateAcknowledgeSuccessfulBinding) Codec() ENDCConfigurationUpdateAcknowledgeValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ENDCConfigurationUpdateAcknowledgeValueCodec{}
	}
	return ENDCConfigurationUpdateAcknowledgeValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value ENDCConfigurationUpdateAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b ENDCConfigurationUpdateAcknowledgeSuccessfulBinding) Build(body ENDCConfigurationUpdateAcknowledge, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// ENDCCellActivationResponseSuccessfulBinding is the concrete SuccessfulBinding[ENDCCellActivationResponse].
type ENDCCellActivationResponseSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(ENDCCellActivationResponse, aper.DecodeState) (ENDCCellActivationResponse, aper.Snapshot)
	compare  func(ENDCCellActivationResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*ENDCCellActivationResponse, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*ENDCCellActivationResponse, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (ENDCCellActivationResponse, error)
	inject   func(ENDCCellActivationResponse) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b ENDCCellActivationResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b ENDCCellActivationResponseSuccessfulBinding) Codec() ENDCCellActivationResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ENDCCellActivationResponseValueCodec{}
	}
	return ENDCCellActivationResponseValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value ENDCCellActivationResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b ENDCCellActivationResponseSuccessfulBinding) Build(body ENDCCellActivationResponse, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// ENDCPartialResetConfirmSuccessfulBinding is the concrete SuccessfulBinding[ENDCPartialResetConfirm].
type ENDCPartialResetConfirmSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(ENDCPartialResetConfirm, aper.DecodeState) (ENDCPartialResetConfirm, aper.Snapshot)
	compare  func(ENDCPartialResetConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*ENDCPartialResetConfirm, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*ENDCPartialResetConfirm, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (ENDCPartialResetConfirm, error)
	inject   func(ENDCPartialResetConfirm) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b ENDCPartialResetConfirmSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b ENDCPartialResetConfirmSuccessfulBinding) Codec() ENDCPartialResetConfirmValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ENDCPartialResetConfirmValueCodec{}
	}
	return ENDCPartialResetConfirmValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value ENDCPartialResetConfirm, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b ENDCPartialResetConfirmSuccessfulBinding) Build(body ENDCPartialResetConfirm, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// EUTRANRCellResourceCoordinationResponseSuccessfulBinding is the concrete SuccessfulBinding[EUTRANRCellResourceCoordinationResponse].
type EUTRANRCellResourceCoordinationResponseSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(EUTRANRCellResourceCoordinationResponse, aper.DecodeState) (EUTRANRCellResourceCoordinationResponse, aper.Snapshot)
	compare  func(EUTRANRCellResourceCoordinationResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*EUTRANRCellResourceCoordinationResponse, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*EUTRANRCellResourceCoordinationResponse, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (EUTRANRCellResourceCoordinationResponse, error)
	inject   func(EUTRANRCellResourceCoordinationResponse) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b EUTRANRCellResourceCoordinationResponseSuccessfulBinding) Info() s00.ProcedureInfo {
	return b.info
}

// Codec returns the complete APER codec for the bound source value.
func (b EUTRANRCellResourceCoordinationResponseSuccessfulBinding) Codec() EUTRANRCellResourceCoordinationResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return EUTRANRCellResourceCoordinationResponseValueCodec{}
	}
	return EUTRANRCellResourceCoordinationResponseValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value EUTRANRCellResourceCoordinationResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b EUTRANRCellResourceCoordinationResponseSuccessfulBinding) Build(body EUTRANRCellResourceCoordinationResponse, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// ENDCX2RemovalResponseSuccessfulBinding is the concrete SuccessfulBinding[ENDCX2RemovalResponse].
type ENDCX2RemovalResponseSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(ENDCX2RemovalResponse, aper.DecodeState) (ENDCX2RemovalResponse, aper.Snapshot)
	compare  func(ENDCX2RemovalResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*ENDCX2RemovalResponse, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*ENDCX2RemovalResponse, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (ENDCX2RemovalResponse, error)
	inject   func(ENDCX2RemovalResponse) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b ENDCX2RemovalResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b ENDCX2RemovalResponseSuccessfulBinding) Codec() ENDCX2RemovalResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ENDCX2RemovalResponseValueCodec{}
	}
	return ENDCX2RemovalResponseValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value ENDCX2RemovalResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b ENDCX2RemovalResponseSuccessfulBinding) Build(body ENDCX2RemovalResponse, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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

// ENDCResourceStatusResponseSuccessfulBinding is the concrete SuccessfulBinding[ENDCResourceStatusResponse].
type ENDCResourceStatusResponseSuccessfulBinding struct {
	context  s00.X2apInternalCodecContext
	capture  func(ENDCResourceStatusResponse, aper.DecodeState) (ENDCResourceStatusResponse, aper.Snapshot)
	compare  func(ENDCResourceStatusResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*ENDCResourceStatusResponse, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*ENDCResourceStatusResponse, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (ENDCResourceStatusResponse, error)
	inject   func(ENDCResourceStatusResponse) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b ENDCResourceStatusResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b ENDCResourceStatusResponseSuccessfulBinding) Codec() ENDCResourceStatusResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ENDCResourceStatusResponseValueCodec{}
	}
	return ENDCResourceStatusResponseValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value ENDCResourceStatusResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b ENDCResourceStatusResponseSuccessfulBinding) Build(body ENDCResourceStatusResponse, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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
	context  s00.X2apInternalCodecContext
	capture  func(UERadioCapabilityIDMappingResponse, aper.DecodeState) (UERadioCapabilityIDMappingResponse, aper.Snapshot)
	compare  func(UERadioCapabilityIDMappingResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*UERadioCapabilityIDMappingResponse, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*UERadioCapabilityIDMappingResponse, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponse, error)
	inject   func(UERadioCapabilityIDMappingResponse) SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b UERadioCapabilityIDMappingResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b UERadioCapabilityIDMappingResponseSuccessfulBinding) Codec() UERadioCapabilityIDMappingResponseValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return UERadioCapabilityIDMappingResponseValueCodec{}
	}
	return UERadioCapabilityIDMappingResponseValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value UERadioCapabilityIDMappingResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b UERadioCapabilityIDMappingResponseSuccessfulBinding) Build(body UERadioCapabilityIDMappingResponse, options ...aper.BuildOption) (SuccessfulOutcome, error) {
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
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
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
func X2apInternalENDCPartialResetRequiredIEValuecaptureX2APProtocolIEContainer(v *s18.ENDCPartialResetRequiredIEContainer, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			X2apInternalENDCPartialResetRequiredIEValuecaptureX2APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func X2apInternalENDCPartialResetRequiredIEValuecompareX2APProtocolIEContainer(v *s18.ENDCPartialResetRequiredIEContainer, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			X2apInternalENDCPartialResetRequiredIEValuecompareX2APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// CellActivationResponseValueCodec is the concrete ValueCodec[CellActivationResponse].
type CellActivationResponseValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(CellActivationResponse, aper.DecodeState) (CellActivationResponse, aper.Snapshot)
	compare func(CellActivationResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (CellActivationResponse, error)
	encode  func(CellActivationResponse, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c CellActivationResponseValueCodec) New(value CellActivationResponse) (CellActivationResponseAPERValue, error) {
	if c.encode == nil {
		return CellActivationResponseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return CellActivationResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellActivationResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return CellActivationResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c CellActivationResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (CellActivationResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return CellActivationResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return CellActivationResponseAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return CellActivationResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return CellActivationResponseAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c CellActivationResponseValueCodec) EncodeAPER(value CellActivationResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalCellActivationResponseValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalCellActivationResponseValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalCellActivationResponseValueCodecEncodeUnplanned(c CellActivationResponseValueCodec, value CellActivationResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalCellActivationResponseValueCodecEncodeChanged(c CellActivationResponseValueCodec, value CellActivationResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENBConfigurationUpdateAcknowledgeValueCodec is the concrete ValueCodec[ENBConfigurationUpdateAcknowledge].
type ENBConfigurationUpdateAcknowledgeValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(ENBConfigurationUpdateAcknowledge, aper.DecodeState) (ENBConfigurationUpdateAcknowledge, aper.Snapshot)
	compare func(ENBConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledge, error)
	encode  func(ENBConfigurationUpdateAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c ENBConfigurationUpdateAcknowledgeValueCodec) New(value ENBConfigurationUpdateAcknowledge) (ENBConfigurationUpdateAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return ENBConfigurationUpdateAcknowledgeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENBConfigurationUpdateAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENBConfigurationUpdateAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ENBConfigurationUpdateAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c ENBConfigurationUpdateAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENBConfigurationUpdateAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ENBConfigurationUpdateAcknowledgeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return ENBConfigurationUpdateAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return ENBConfigurationUpdateAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return ENBConfigurationUpdateAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c ENBConfigurationUpdateAcknowledgeValueCodec) EncodeAPER(value ENBConfigurationUpdateAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalENBConfigurationUpdateAcknowledgeValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalENBConfigurationUpdateAcknowledgeValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalENBConfigurationUpdateAcknowledgeValueCodecEncodeUnplanned(c ENBConfigurationUpdateAcknowledgeValueCodec, value ENBConfigurationUpdateAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalENBConfigurationUpdateAcknowledgeValueCodecEncodeChanged(c ENBConfigurationUpdateAcknowledgeValueCodec, value ENBConfigurationUpdateAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCCellActivationResponseValueCodec is the concrete ValueCodec[ENDCCellActivationResponse].
type ENDCCellActivationResponseValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(ENDCCellActivationResponse, aper.DecodeState) (ENDCCellActivationResponse, aper.Snapshot)
	compare func(ENDCCellActivationResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (ENDCCellActivationResponse, error)
	encode  func(ENDCCellActivationResponse, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c ENDCCellActivationResponseValueCodec) New(value ENDCCellActivationResponse) (ENDCCellActivationResponseAPERValue, error) {
	if c.encode == nil {
		return ENDCCellActivationResponseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCCellActivationResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCCellActivationResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ENDCCellActivationResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c ENDCCellActivationResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCCellActivationResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ENDCCellActivationResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return ENDCCellActivationResponseAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return ENDCCellActivationResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return ENDCCellActivationResponseAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c ENDCCellActivationResponseValueCodec) EncodeAPER(value ENDCCellActivationResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalENDCCellActivationResponseValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalENDCCellActivationResponseValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalENDCCellActivationResponseValueCodecEncodeUnplanned(c ENDCCellActivationResponseValueCodec, value ENDCCellActivationResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalENDCCellActivationResponseValueCodecEncodeChanged(c ENDCCellActivationResponseValueCodec, value ENDCCellActivationResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCConfigurationUpdateAcknowledgeValueCodec is the concrete ValueCodec[ENDCConfigurationUpdateAcknowledge].
type ENDCConfigurationUpdateAcknowledgeValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(ENDCConfigurationUpdateAcknowledge, aper.DecodeState) (ENDCConfigurationUpdateAcknowledge, aper.Snapshot)
	compare func(ENDCConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (ENDCConfigurationUpdateAcknowledge, error)
	encode  func(ENDCConfigurationUpdateAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c ENDCConfigurationUpdateAcknowledgeValueCodec) New(value ENDCConfigurationUpdateAcknowledge) (ENDCConfigurationUpdateAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return ENDCConfigurationUpdateAcknowledgeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCConfigurationUpdateAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCConfigurationUpdateAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ENDCConfigurationUpdateAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c ENDCConfigurationUpdateAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCConfigurationUpdateAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ENDCConfigurationUpdateAcknowledgeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return ENDCConfigurationUpdateAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return ENDCConfigurationUpdateAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return ENDCConfigurationUpdateAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c ENDCConfigurationUpdateAcknowledgeValueCodec) EncodeAPER(value ENDCConfigurationUpdateAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalENDCConfigurationUpdateAcknowledgeValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalENDCConfigurationUpdateAcknowledgeValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalENDCConfigurationUpdateAcknowledgeValueCodecEncodeUnplanned(c ENDCConfigurationUpdateAcknowledgeValueCodec, value ENDCConfigurationUpdateAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalENDCConfigurationUpdateAcknowledgeValueCodecEncodeChanged(c ENDCConfigurationUpdateAcknowledgeValueCodec, value ENDCConfigurationUpdateAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCPartialResetConfirmValueCodec is the concrete ValueCodec[ENDCPartialResetConfirm].
type ENDCPartialResetConfirmValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(ENDCPartialResetConfirm, aper.DecodeState) (ENDCPartialResetConfirm, aper.Snapshot)
	compare func(ENDCPartialResetConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (ENDCPartialResetConfirm, error)
	encode  func(ENDCPartialResetConfirm, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c ENDCPartialResetConfirmValueCodec) New(value ENDCPartialResetConfirm) (ENDCPartialResetConfirmAPERValue, error) {
	if c.encode == nil {
		return ENDCPartialResetConfirmAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCPartialResetConfirmAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCPartialResetConfirmAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ENDCPartialResetConfirmAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c ENDCPartialResetConfirmValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCPartialResetConfirmAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ENDCPartialResetConfirmAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return ENDCPartialResetConfirmAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return ENDCPartialResetConfirmAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return ENDCPartialResetConfirmAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c ENDCPartialResetConfirmValueCodec) EncodeAPER(value ENDCPartialResetConfirmAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalENDCPartialResetConfirmValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalENDCPartialResetConfirmValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalENDCPartialResetConfirmValueCodecEncodeUnplanned(c ENDCPartialResetConfirmValueCodec, value ENDCPartialResetConfirm, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalENDCPartialResetConfirmValueCodecEncodeChanged(c ENDCPartialResetConfirmValueCodec, value ENDCPartialResetConfirm, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCResourceStatusResponseValueCodec is the concrete ValueCodec[ENDCResourceStatusResponse].
type ENDCResourceStatusResponseValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(ENDCResourceStatusResponse, aper.DecodeState) (ENDCResourceStatusResponse, aper.Snapshot)
	compare func(ENDCResourceStatusResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (ENDCResourceStatusResponse, error)
	encode  func(ENDCResourceStatusResponse, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c ENDCResourceStatusResponseValueCodec) New(value ENDCResourceStatusResponse) (ENDCResourceStatusResponseAPERValue, error) {
	if c.encode == nil {
		return ENDCResourceStatusResponseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCResourceStatusResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCResourceStatusResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ENDCResourceStatusResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c ENDCResourceStatusResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCResourceStatusResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ENDCResourceStatusResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return ENDCResourceStatusResponseAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return ENDCResourceStatusResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return ENDCResourceStatusResponseAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c ENDCResourceStatusResponseValueCodec) EncodeAPER(value ENDCResourceStatusResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalENDCResourceStatusResponseValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalENDCResourceStatusResponseValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalENDCResourceStatusResponseValueCodecEncodeUnplanned(c ENDCResourceStatusResponseValueCodec, value ENDCResourceStatusResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalENDCResourceStatusResponseValueCodecEncodeChanged(c ENDCResourceStatusResponseValueCodec, value ENDCResourceStatusResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCX2RemovalResponseValueCodec is the concrete ValueCodec[ENDCX2RemovalResponse].
type ENDCX2RemovalResponseValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(ENDCX2RemovalResponse, aper.DecodeState) (ENDCX2RemovalResponse, aper.Snapshot)
	compare func(ENDCX2RemovalResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (ENDCX2RemovalResponse, error)
	encode  func(ENDCX2RemovalResponse, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c ENDCX2RemovalResponseValueCodec) New(value ENDCX2RemovalResponse) (ENDCX2RemovalResponseAPERValue, error) {
	if c.encode == nil {
		return ENDCX2RemovalResponseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCX2RemovalResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCX2RemovalResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ENDCX2RemovalResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c ENDCX2RemovalResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCX2RemovalResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ENDCX2RemovalResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return ENDCX2RemovalResponseAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return ENDCX2RemovalResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return ENDCX2RemovalResponseAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c ENDCX2RemovalResponseValueCodec) EncodeAPER(value ENDCX2RemovalResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalENDCX2RemovalResponseValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalENDCX2RemovalResponseValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalENDCX2RemovalResponseValueCodecEncodeUnplanned(c ENDCX2RemovalResponseValueCodec, value ENDCX2RemovalResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalENDCX2RemovalResponseValueCodecEncodeChanged(c ENDCX2RemovalResponseValueCodec, value ENDCX2RemovalResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ENDCX2SetupResponseValueCodec is the concrete ValueCodec[ENDCX2SetupResponse].
type ENDCX2SetupResponseValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(ENDCX2SetupResponse, aper.DecodeState) (ENDCX2SetupResponse, aper.Snapshot)
	compare func(ENDCX2SetupResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (ENDCX2SetupResponse, error)
	encode  func(ENDCX2SetupResponse, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c ENDCX2SetupResponseValueCodec) New(value ENDCX2SetupResponse) (ENDCX2SetupResponseAPERValue, error) {
	if c.encode == nil {
		return ENDCX2SetupResponseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ENDCX2SetupResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ENDCX2SetupResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ENDCX2SetupResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c ENDCX2SetupResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ENDCX2SetupResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ENDCX2SetupResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return ENDCX2SetupResponseAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return ENDCX2SetupResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return ENDCX2SetupResponseAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c ENDCX2SetupResponseValueCodec) EncodeAPER(value ENDCX2SetupResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalENDCX2SetupResponseValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalENDCX2SetupResponseValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalENDCX2SetupResponseValueCodecEncodeUnplanned(c ENDCX2SetupResponseValueCodec, value ENDCX2SetupResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalENDCX2SetupResponseValueCodecEncodeChanged(c ENDCX2SetupResponseValueCodec, value ENDCX2SetupResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// EUTRANRCellResourceCoordinationResponseValueCodec is the concrete ValueCodec[EUTRANRCellResourceCoordinationResponse].
type EUTRANRCellResourceCoordinationResponseValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(EUTRANRCellResourceCoordinationResponse, aper.DecodeState) (EUTRANRCellResourceCoordinationResponse, aper.Snapshot)
	compare func(EUTRANRCellResourceCoordinationResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (EUTRANRCellResourceCoordinationResponse, error)
	encode  func(EUTRANRCellResourceCoordinationResponse, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c EUTRANRCellResourceCoordinationResponseValueCodec) New(value EUTRANRCellResourceCoordinationResponse) (EUTRANRCellResourceCoordinationResponseAPERValue, error) {
	if c.encode == nil {
		return EUTRANRCellResourceCoordinationResponseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EUTRANRCellResourceCoordinationResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EUTRANRCellResourceCoordinationResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return EUTRANRCellResourceCoordinationResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c EUTRANRCellResourceCoordinationResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EUTRANRCellResourceCoordinationResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return EUTRANRCellResourceCoordinationResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return EUTRANRCellResourceCoordinationResponseAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return EUTRANRCellResourceCoordinationResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return EUTRANRCellResourceCoordinationResponseAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c EUTRANRCellResourceCoordinationResponseValueCodec) EncodeAPER(value EUTRANRCellResourceCoordinationResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalEUTRANRCellResourceCoordinationResponseValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalEUTRANRCellResourceCoordinationResponseValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalEUTRANRCellResourceCoordinationResponseValueCodecEncodeUnplanned(c EUTRANRCellResourceCoordinationResponseValueCodec, value EUTRANRCellResourceCoordinationResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalEUTRANRCellResourceCoordinationResponseValueCodecEncodeChanged(c EUTRANRCellResourceCoordinationResponseValueCodec, value EUTRANRCellResourceCoordinationResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverRequestAcknowledgeValueCodec is the concrete ValueCodec[HandoverRequestAcknowledge].
type HandoverRequestAcknowledgeValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(HandoverRequestAcknowledge, aper.DecodeState) (HandoverRequestAcknowledge, aper.Snapshot)
	compare func(HandoverRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (HandoverRequestAcknowledge, error)
	encode  func(HandoverRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c HandoverRequestAcknowledgeValueCodec) New(value HandoverRequestAcknowledge) (HandoverRequestAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return HandoverRequestAcknowledgeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequestAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return HandoverRequestAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c HandoverRequestAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequestAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return HandoverRequestAcknowledgeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return HandoverRequestAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return HandoverRequestAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return HandoverRequestAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c HandoverRequestAcknowledgeValueCodec) EncodeAPER(value HandoverRequestAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalHandoverRequestAcknowledgeValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalHandoverRequestAcknowledgeValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalHandoverRequestAcknowledgeValueCodecEncodeUnplanned(c HandoverRequestAcknowledgeValueCodec, value HandoverRequestAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalHandoverRequestAcknowledgeValueCodecEncodeChanged(c HandoverRequestAcknowledgeValueCodec, value HandoverRequestAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MobilityChangeAcknowledgeValueCodec is the concrete ValueCodec[MobilityChangeAcknowledge].
type MobilityChangeAcknowledgeValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(MobilityChangeAcknowledge, aper.DecodeState) (MobilityChangeAcknowledge, aper.Snapshot)
	compare func(MobilityChangeAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (MobilityChangeAcknowledge, error)
	encode  func(MobilityChangeAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c MobilityChangeAcknowledgeValueCodec) New(value MobilityChangeAcknowledge) (MobilityChangeAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return MobilityChangeAcknowledgeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MobilityChangeAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MobilityChangeAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return MobilityChangeAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c MobilityChangeAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MobilityChangeAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MobilityChangeAcknowledgeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return MobilityChangeAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return MobilityChangeAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return MobilityChangeAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c MobilityChangeAcknowledgeValueCodec) EncodeAPER(value MobilityChangeAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalMobilityChangeAcknowledgeValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalMobilityChangeAcknowledgeValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalMobilityChangeAcknowledgeValueCodecEncodeUnplanned(c MobilityChangeAcknowledgeValueCodec, value MobilityChangeAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalMobilityChangeAcknowledgeValueCodecEncodeChanged(c MobilityChangeAcknowledgeValueCodec, value MobilityChangeAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetResponseValueCodec is the concrete ValueCodec[ResetResponse].
type ResetResponseValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(ResetResponse, aper.DecodeState) (ResetResponse, aper.Snapshot)
	compare func(ResetResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (ResetResponse, error)
	encode  func(ResetResponse, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c ResetResponseValueCodec) New(value ResetResponse) (ResetResponseAPERValue, error) {
	if c.encode == nil {
		return ResetResponseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ResetResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c ResetResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResetResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return ResetResponseAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return ResetResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return ResetResponseAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c ResetResponseValueCodec) EncodeAPER(value ResetResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalResetResponseValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalResetResponseValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalResetResponseValueCodecEncodeUnplanned(c ResetResponseValueCodec, value ResetResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalResetResponseValueCodecEncodeChanged(c ResetResponseValueCodec, value ResetResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResourceStatusResponseValueCodec is the concrete ValueCodec[ResourceStatusResponse].
type ResourceStatusResponseValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(ResourceStatusResponse, aper.DecodeState) (ResourceStatusResponse, aper.Snapshot)
	compare func(ResourceStatusResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (ResourceStatusResponse, error)
	encode  func(ResourceStatusResponse, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c ResourceStatusResponseValueCodec) New(value ResourceStatusResponse) (ResourceStatusResponseAPERValue, error) {
	if c.encode == nil {
		return ResourceStatusResponseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResourceStatusResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResourceStatusResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ResourceStatusResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c ResourceStatusResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResourceStatusResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResourceStatusResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return ResourceStatusResponseAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return ResourceStatusResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return ResourceStatusResponseAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c ResourceStatusResponseValueCodec) EncodeAPER(value ResourceStatusResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalResourceStatusResponseValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalResourceStatusResponseValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalResourceStatusResponseValueCodecEncodeUnplanned(c ResourceStatusResponseValueCodec, value ResourceStatusResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalResourceStatusResponseValueCodecEncodeChanged(c ResourceStatusResponseValueCodec, value ResourceStatusResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RetrieveUEContextResponseValueCodec is the concrete ValueCodec[RetrieveUEContextResponse].
type RetrieveUEContextResponseValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(RetrieveUEContextResponse, aper.DecodeState) (RetrieveUEContextResponse, aper.Snapshot)
	compare func(RetrieveUEContextResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (RetrieveUEContextResponse, error)
	encode  func(RetrieveUEContextResponse, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c RetrieveUEContextResponseValueCodec) New(value RetrieveUEContextResponse) (RetrieveUEContextResponseAPERValue, error) {
	if c.encode == nil {
		return RetrieveUEContextResponseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RetrieveUEContextResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RetrieveUEContextResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return RetrieveUEContextResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c RetrieveUEContextResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RetrieveUEContextResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return RetrieveUEContextResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return RetrieveUEContextResponseAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return RetrieveUEContextResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return RetrieveUEContextResponseAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c RetrieveUEContextResponseValueCodec) EncodeAPER(value RetrieveUEContextResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalRetrieveUEContextResponseValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalRetrieveUEContextResponseValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalRetrieveUEContextResponseValueCodecEncodeUnplanned(c RetrieveUEContextResponseValueCodec, value RetrieveUEContextResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalRetrieveUEContextResponseValueCodecEncodeChanged(c RetrieveUEContextResponseValueCodec, value RetrieveUEContextResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SeNBAdditionRequestAcknowledgeValueCodec is the concrete ValueCodec[SeNBAdditionRequestAcknowledge].
type SeNBAdditionRequestAcknowledgeValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(SeNBAdditionRequestAcknowledge, aper.DecodeState) (SeNBAdditionRequestAcknowledge, aper.Snapshot)
	compare func(SeNBAdditionRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (SeNBAdditionRequestAcknowledge, error)
	encode  func(SeNBAdditionRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c SeNBAdditionRequestAcknowledgeValueCodec) New(value SeNBAdditionRequestAcknowledge) (SeNBAdditionRequestAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return SeNBAdditionRequestAcknowledgeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SeNBAdditionRequestAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SeNBAdditionRequestAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SeNBAdditionRequestAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c SeNBAdditionRequestAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SeNBAdditionRequestAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SeNBAdditionRequestAcknowledgeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return SeNBAdditionRequestAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return SeNBAdditionRequestAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return SeNBAdditionRequestAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c SeNBAdditionRequestAcknowledgeValueCodec) EncodeAPER(value SeNBAdditionRequestAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalSeNBAdditionRequestAcknowledgeValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalSeNBAdditionRequestAcknowledgeValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalSeNBAdditionRequestAcknowledgeValueCodecEncodeUnplanned(c SeNBAdditionRequestAcknowledgeValueCodec, value SeNBAdditionRequestAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalSeNBAdditionRequestAcknowledgeValueCodecEncodeChanged(c SeNBAdditionRequestAcknowledgeValueCodec, value SeNBAdditionRequestAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SeNBModificationConfirmValueCodec is the concrete ValueCodec[SeNBModificationConfirm].
type SeNBModificationConfirmValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(SeNBModificationConfirm, aper.DecodeState) (SeNBModificationConfirm, aper.Snapshot)
	compare func(SeNBModificationConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (SeNBModificationConfirm, error)
	encode  func(SeNBModificationConfirm, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c SeNBModificationConfirmValueCodec) New(value SeNBModificationConfirm) (SeNBModificationConfirmAPERValue, error) {
	if c.encode == nil {
		return SeNBModificationConfirmAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SeNBModificationConfirmAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SeNBModificationConfirmAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SeNBModificationConfirmAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c SeNBModificationConfirmValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SeNBModificationConfirmAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SeNBModificationConfirmAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return SeNBModificationConfirmAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return SeNBModificationConfirmAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return SeNBModificationConfirmAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c SeNBModificationConfirmValueCodec) EncodeAPER(value SeNBModificationConfirmAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalSeNBModificationConfirmValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalSeNBModificationConfirmValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalSeNBModificationConfirmValueCodecEncodeUnplanned(c SeNBModificationConfirmValueCodec, value SeNBModificationConfirm, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalSeNBModificationConfirmValueCodecEncodeChanged(c SeNBModificationConfirmValueCodec, value SeNBModificationConfirm, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SeNBModificationRequestAcknowledgeValueCodec is the concrete ValueCodec[SeNBModificationRequestAcknowledge].
type SeNBModificationRequestAcknowledgeValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(SeNBModificationRequestAcknowledge, aper.DecodeState) (SeNBModificationRequestAcknowledge, aper.Snapshot)
	compare func(SeNBModificationRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (SeNBModificationRequestAcknowledge, error)
	encode  func(SeNBModificationRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c SeNBModificationRequestAcknowledgeValueCodec) New(value SeNBModificationRequestAcknowledge) (SeNBModificationRequestAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return SeNBModificationRequestAcknowledgeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SeNBModificationRequestAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SeNBModificationRequestAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SeNBModificationRequestAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c SeNBModificationRequestAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SeNBModificationRequestAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SeNBModificationRequestAcknowledgeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return SeNBModificationRequestAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return SeNBModificationRequestAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return SeNBModificationRequestAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c SeNBModificationRequestAcknowledgeValueCodec) EncodeAPER(value SeNBModificationRequestAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalSeNBModificationRequestAcknowledgeValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalSeNBModificationRequestAcknowledgeValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalSeNBModificationRequestAcknowledgeValueCodecEncodeUnplanned(c SeNBModificationRequestAcknowledgeValueCodec, value SeNBModificationRequestAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalSeNBModificationRequestAcknowledgeValueCodecEncodeChanged(c SeNBModificationRequestAcknowledgeValueCodec, value SeNBModificationRequestAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SeNBReleaseConfirmValueCodec is the concrete ValueCodec[SeNBReleaseConfirm].
type SeNBReleaseConfirmValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(SeNBReleaseConfirm, aper.DecodeState) (SeNBReleaseConfirm, aper.Snapshot)
	compare func(SeNBReleaseConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (SeNBReleaseConfirm, error)
	encode  func(SeNBReleaseConfirm, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c SeNBReleaseConfirmValueCodec) New(value SeNBReleaseConfirm) (SeNBReleaseConfirmAPERValue, error) {
	if c.encode == nil {
		return SeNBReleaseConfirmAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SeNBReleaseConfirmAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SeNBReleaseConfirmAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SeNBReleaseConfirmAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c SeNBReleaseConfirmValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SeNBReleaseConfirmAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SeNBReleaseConfirmAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return SeNBReleaseConfirmAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return SeNBReleaseConfirmAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return SeNBReleaseConfirmAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c SeNBReleaseConfirmValueCodec) EncodeAPER(value SeNBReleaseConfirmAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalSeNBReleaseConfirmValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalSeNBReleaseConfirmValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalSeNBReleaseConfirmValueCodecEncodeUnplanned(c SeNBReleaseConfirmValueCodec, value SeNBReleaseConfirm, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalSeNBReleaseConfirmValueCodecEncodeChanged(c SeNBReleaseConfirmValueCodec, value SeNBReleaseConfirm, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SgNBAdditionRequestAcknowledgeValueCodec is the concrete ValueCodec[SgNBAdditionRequestAcknowledge].
type SgNBAdditionRequestAcknowledgeValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(SgNBAdditionRequestAcknowledge, aper.DecodeState) (SgNBAdditionRequestAcknowledge, aper.Snapshot)
	compare func(SgNBAdditionRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (SgNBAdditionRequestAcknowledge, error)
	encode  func(SgNBAdditionRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c SgNBAdditionRequestAcknowledgeValueCodec) New(value SgNBAdditionRequestAcknowledge) (SgNBAdditionRequestAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return SgNBAdditionRequestAcknowledgeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SgNBAdditionRequestAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SgNBAdditionRequestAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SgNBAdditionRequestAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c SgNBAdditionRequestAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SgNBAdditionRequestAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SgNBAdditionRequestAcknowledgeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return SgNBAdditionRequestAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return SgNBAdditionRequestAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return SgNBAdditionRequestAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c SgNBAdditionRequestAcknowledgeValueCodec) EncodeAPER(value SgNBAdditionRequestAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalSgNBAdditionRequestAcknowledgeValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalSgNBAdditionRequestAcknowledgeValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalSgNBAdditionRequestAcknowledgeValueCodecEncodeUnplanned(c SgNBAdditionRequestAcknowledgeValueCodec, value SgNBAdditionRequestAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalSgNBAdditionRequestAcknowledgeValueCodecEncodeChanged(c SgNBAdditionRequestAcknowledgeValueCodec, value SgNBAdditionRequestAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SgNBChangeConfirmValueCodec is the concrete ValueCodec[SgNBChangeConfirm].
type SgNBChangeConfirmValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(SgNBChangeConfirm, aper.DecodeState) (SgNBChangeConfirm, aper.Snapshot)
	compare func(SgNBChangeConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (SgNBChangeConfirm, error)
	encode  func(SgNBChangeConfirm, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c SgNBChangeConfirmValueCodec) New(value SgNBChangeConfirm) (SgNBChangeConfirmAPERValue, error) {
	if c.encode == nil {
		return SgNBChangeConfirmAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SgNBChangeConfirmAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SgNBChangeConfirmAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SgNBChangeConfirmAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c SgNBChangeConfirmValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SgNBChangeConfirmAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SgNBChangeConfirmAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return SgNBChangeConfirmAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return SgNBChangeConfirmAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return SgNBChangeConfirmAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c SgNBChangeConfirmValueCodec) EncodeAPER(value SgNBChangeConfirmAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalSgNBChangeConfirmValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalSgNBChangeConfirmValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalSgNBChangeConfirmValueCodecEncodeUnplanned(c SgNBChangeConfirmValueCodec, value SgNBChangeConfirm, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalSgNBChangeConfirmValueCodecEncodeChanged(c SgNBChangeConfirmValueCodec, value SgNBChangeConfirm, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SgNBModificationConfirmValueCodec is the concrete ValueCodec[SgNBModificationConfirm].
type SgNBModificationConfirmValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(SgNBModificationConfirm, aper.DecodeState) (SgNBModificationConfirm, aper.Snapshot)
	compare func(SgNBModificationConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (SgNBModificationConfirm, error)
	encode  func(SgNBModificationConfirm, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c SgNBModificationConfirmValueCodec) New(value SgNBModificationConfirm) (SgNBModificationConfirmAPERValue, error) {
	if c.encode == nil {
		return SgNBModificationConfirmAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SgNBModificationConfirmAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SgNBModificationConfirmAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SgNBModificationConfirmAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c SgNBModificationConfirmValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SgNBModificationConfirmAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SgNBModificationConfirmAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return SgNBModificationConfirmAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return SgNBModificationConfirmAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return SgNBModificationConfirmAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c SgNBModificationConfirmValueCodec) EncodeAPER(value SgNBModificationConfirmAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalSgNBModificationConfirmValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalSgNBModificationConfirmValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalSgNBModificationConfirmValueCodecEncodeUnplanned(c SgNBModificationConfirmValueCodec, value SgNBModificationConfirm, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalSgNBModificationConfirmValueCodecEncodeChanged(c SgNBModificationConfirmValueCodec, value SgNBModificationConfirm, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SgNBModificationRequestAcknowledgeValueCodec is the concrete ValueCodec[SgNBModificationRequestAcknowledge].
type SgNBModificationRequestAcknowledgeValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(SgNBModificationRequestAcknowledge, aper.DecodeState) (SgNBModificationRequestAcknowledge, aper.Snapshot)
	compare func(SgNBModificationRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (SgNBModificationRequestAcknowledge, error)
	encode  func(SgNBModificationRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c SgNBModificationRequestAcknowledgeValueCodec) New(value SgNBModificationRequestAcknowledge) (SgNBModificationRequestAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return SgNBModificationRequestAcknowledgeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SgNBModificationRequestAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SgNBModificationRequestAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SgNBModificationRequestAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c SgNBModificationRequestAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SgNBModificationRequestAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SgNBModificationRequestAcknowledgeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return SgNBModificationRequestAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return SgNBModificationRequestAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return SgNBModificationRequestAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c SgNBModificationRequestAcknowledgeValueCodec) EncodeAPER(value SgNBModificationRequestAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalSgNBModificationRequestAcknowledgeValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalSgNBModificationRequestAcknowledgeValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalSgNBModificationRequestAcknowledgeValueCodecEncodeUnplanned(c SgNBModificationRequestAcknowledgeValueCodec, value SgNBModificationRequestAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalSgNBModificationRequestAcknowledgeValueCodecEncodeChanged(c SgNBModificationRequestAcknowledgeValueCodec, value SgNBModificationRequestAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SgNBReleaseConfirmValueCodec is the concrete ValueCodec[SgNBReleaseConfirm].
type SgNBReleaseConfirmValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(SgNBReleaseConfirm, aper.DecodeState) (SgNBReleaseConfirm, aper.Snapshot)
	compare func(SgNBReleaseConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (SgNBReleaseConfirm, error)
	encode  func(SgNBReleaseConfirm, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c SgNBReleaseConfirmValueCodec) New(value SgNBReleaseConfirm) (SgNBReleaseConfirmAPERValue, error) {
	if c.encode == nil {
		return SgNBReleaseConfirmAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SgNBReleaseConfirmAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SgNBReleaseConfirmAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SgNBReleaseConfirmAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c SgNBReleaseConfirmValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SgNBReleaseConfirmAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SgNBReleaseConfirmAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return SgNBReleaseConfirmAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return SgNBReleaseConfirmAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return SgNBReleaseConfirmAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c SgNBReleaseConfirmValueCodec) EncodeAPER(value SgNBReleaseConfirmAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalSgNBReleaseConfirmValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalSgNBReleaseConfirmValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalSgNBReleaseConfirmValueCodecEncodeUnplanned(c SgNBReleaseConfirmValueCodec, value SgNBReleaseConfirm, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalSgNBReleaseConfirmValueCodecEncodeChanged(c SgNBReleaseConfirmValueCodec, value SgNBReleaseConfirm, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SgNBReleaseRequestAcknowledgeValueCodec is the concrete ValueCodec[SgNBReleaseRequestAcknowledge].
type SgNBReleaseRequestAcknowledgeValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(SgNBReleaseRequestAcknowledge, aper.DecodeState) (SgNBReleaseRequestAcknowledge, aper.Snapshot)
	compare func(SgNBReleaseRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (SgNBReleaseRequestAcknowledge, error)
	encode  func(SgNBReleaseRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c SgNBReleaseRequestAcknowledgeValueCodec) New(value SgNBReleaseRequestAcknowledge) (SgNBReleaseRequestAcknowledgeAPERValue, error) {
	if c.encode == nil {
		return SgNBReleaseRequestAcknowledgeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SgNBReleaseRequestAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SgNBReleaseRequestAcknowledgeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SgNBReleaseRequestAcknowledgeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c SgNBReleaseRequestAcknowledgeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SgNBReleaseRequestAcknowledgeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SgNBReleaseRequestAcknowledgeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return SgNBReleaseRequestAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return SgNBReleaseRequestAcknowledgeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return SgNBReleaseRequestAcknowledgeAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c SgNBReleaseRequestAcknowledgeValueCodec) EncodeAPER(value SgNBReleaseRequestAcknowledgeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalSgNBReleaseRequestAcknowledgeValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalSgNBReleaseRequestAcknowledgeValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalSgNBReleaseRequestAcknowledgeValueCodecEncodeUnplanned(c SgNBReleaseRequestAcknowledgeValueCodec, value SgNBReleaseRequestAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalSgNBReleaseRequestAcknowledgeValueCodecEncodeChanged(c SgNBReleaseRequestAcknowledgeValueCodec, value SgNBReleaseRequestAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SuccessfulOutcomeValueCodec is the concrete ValueCodec[SuccessfulOutcome].
type SuccessfulOutcomeValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(SuccessfulOutcome, aper.DecodeState) (SuccessfulOutcome, aper.Snapshot)
	compare func(SuccessfulOutcome, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (SuccessfulOutcome, error)
	encode  func(SuccessfulOutcome, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c SuccessfulOutcomeValueCodec) New(value SuccessfulOutcome) (SuccessfulOutcomeAPERValue, error) {
	if c.encode == nil {
		return SuccessfulOutcomeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SuccessfulOutcomeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SuccessfulOutcomeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SuccessfulOutcomeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c SuccessfulOutcomeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SuccessfulOutcomeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SuccessfulOutcomeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return SuccessfulOutcomeAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return SuccessfulOutcomeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return SuccessfulOutcomeAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c SuccessfulOutcomeValueCodec) EncodeAPER(value SuccessfulOutcomeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalSuccessfulOutcomeValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalSuccessfulOutcomeValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalSuccessfulOutcomeValueCodecEncodeUnplanned(c SuccessfulOutcomeValueCodec, value SuccessfulOutcome, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalSuccessfulOutcomeValueCodecEncodeChanged(c SuccessfulOutcomeValueCodec, value SuccessfulOutcome, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityIDMappingResponseValueCodec is the concrete ValueCodec[UERadioCapabilityIDMappingResponse].
type UERadioCapabilityIDMappingResponseValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(UERadioCapabilityIDMappingResponse, aper.DecodeState) (UERadioCapabilityIDMappingResponse, aper.Snapshot)
	compare func(UERadioCapabilityIDMappingResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponse, error)
	encode  func(UERadioCapabilityIDMappingResponse, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c UERadioCapabilityIDMappingResponseValueCodec) New(value UERadioCapabilityIDMappingResponse) (UERadioCapabilityIDMappingResponseAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityIDMappingResponseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return UERadioCapabilityIDMappingResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c UERadioCapabilityIDMappingResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityIDMappingResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UERadioCapabilityIDMappingResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return UERadioCapabilityIDMappingResponseAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return UERadioCapabilityIDMappingResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return UERadioCapabilityIDMappingResponseAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c UERadioCapabilityIDMappingResponseValueCodec) EncodeAPER(value UERadioCapabilityIDMappingResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalUERadioCapabilityIDMappingResponseValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalUERadioCapabilityIDMappingResponseValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalUERadioCapabilityIDMappingResponseValueCodecEncodeUnplanned(c UERadioCapabilityIDMappingResponseValueCodec, value UERadioCapabilityIDMappingResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalUERadioCapabilityIDMappingResponseValueCodecEncodeChanged(c UERadioCapabilityIDMappingResponseValueCodec, value UERadioCapabilityIDMappingResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// X2RemovalResponseValueCodec is the concrete ValueCodec[X2RemovalResponse].
type X2RemovalResponseValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(X2RemovalResponse, aper.DecodeState) (X2RemovalResponse, aper.Snapshot)
	compare func(X2RemovalResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (X2RemovalResponse, error)
	encode  func(X2RemovalResponse, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c X2RemovalResponseValueCodec) New(value X2RemovalResponse) (X2RemovalResponseAPERValue, error) {
	if c.encode == nil {
		return X2RemovalResponseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return X2RemovalResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return X2RemovalResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return X2RemovalResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c X2RemovalResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (X2RemovalResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return X2RemovalResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return X2RemovalResponseAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return X2RemovalResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return X2RemovalResponseAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c X2RemovalResponseValueCodec) EncodeAPER(value X2RemovalResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalX2RemovalResponseValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalX2RemovalResponseValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalX2RemovalResponseValueCodecEncodeUnplanned(c X2RemovalResponseValueCodec, value X2RemovalResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalX2RemovalResponseValueCodecEncodeChanged(c X2RemovalResponseValueCodec, value X2RemovalResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// X2SetupResponseValueCodec is the concrete ValueCodec[X2SetupResponse].
type X2SetupResponseValueCodec struct {
	context s00.X2apInternalCodecContext
	capture func(X2SetupResponse, aper.DecodeState) (X2SetupResponse, aper.Snapshot)
	compare func(X2SetupResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (X2SetupResponse, error)
	encode  func(X2SetupResponse, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c X2SetupResponseValueCodec) New(value X2SetupResponse) (X2SetupResponseAPERValue, error) {
	if c.encode == nil {
		return X2SetupResponseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return X2SetupResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return X2SetupResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return X2SetupResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c X2SetupResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (X2SetupResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return X2SetupResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	value, err := c.decode(data, settings)
	if err == nil {
		if c.capture == nil {
			err = fmt.Errorf("%w: missing semantic visitor", aper.ErrInvalidValue)
		} else {
			value, replay := c.capture(value, settings)
			report, err := aper.FinishDecode(settings, nil)
			if err != nil {
				return X2SetupResponseAPERValue{}, report, aper.OperationError(err, c.path)
			}
			return X2SetupResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return X2SetupResponseAPERValue{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c X2SetupResponseValueCodec) EncodeAPER(value X2SetupResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {
		plan := c.compare(value.Value, value.replay, budget)
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := value.received.EncodePlanBytes(plan)
			return out, aper.OperationError(err, c.path)
		}
		return X2apInternalX2SetupResponseValueCodecEncodeChanged(c, value.Value, fresh, plan)
	}
	return X2apInternalX2SetupResponseValueCodecEncodeUnplanned(c, value.Value, fresh, budget)
}
func X2apInternalX2SetupResponseValueCodecEncodeUnplanned(c X2SetupResponseValueCodec, value X2SetupResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func X2apInternalX2SetupResponseValueCodecEncodeChanged(c X2SetupResponseValueCodec, value X2SetupResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TS 36.423 V19.1.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func X2apInternalENDCPartialResetConfirmIEValuevalidateX2APIEContainer(fields s18.ENDCPartialResetConfirmIEContainer, rows []s06.FieldInfo, path string, budget *aper.DecodeBudget,

) s12.ValidationReport {
	report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(true, budget)
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s12.X2apInternalValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s12.X2apInternalValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.423 V19.1.0 §9.3.8 binds the selected value to @id.
		if !s18.X2apInternalENDCPartialResetConfirmIEValueMatchesID(field.Value, field.Id, budget) {
			rule := s18.X2apInternalENDCPartialResetConfirmIEValueRule(field.Value)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: s00.X2apInternalConstructT7TableIDF6source(rule.Assignment), IEID: field.Id, HasIEID: true, Rule: s00.X2apInternalX2apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := s00.X2apInternalConstructT7TableIDF6source(s18.X2apInternalENDCPartialResetConfirmIEValueRule(field.Value).Assignment)
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s00.X2apInternalX2apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s00.X2apInternalX2apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.X2apInternalKnownX2APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s00.X2apInternalX2apValidationRule(s00.NotAllowed), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s00.X2apInternalX2apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s00.X2apInternalX2apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s00.X2apInternalX2apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s00.X2apInternalX2apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s00.X2apInternalX2apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s12.X2apInternalValidationReportAddDeferred(&report, s06.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func X2apInternalENDCPartialResetRequiredIEValuecaptureX2APProtocolIEField(v *s18.ENDCPartialResetRequiredIEField, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s00.X2apInternalCaptureX2APProtocolIEID(&v.Id, s)
	s00.X2apInternalCaptureX2APCriticality(&v.Criticality, s)
	v.Value = s18.X2apInternalENDCPartialResetRequiredIEValueCaptureSemantics(v.Value, *s)
	s.End(f, s18.X2apInternalENDCPartialResetRequiredIEFieldFieldReplay(v), *s18.X2apInternalENDCPartialResetRequiredIEFieldFieldWithoutReplay(v))
}
func X2apInternalENDCPartialResetRequiredIEValuecompareX2APProtocolIEField(v *s18.ENDCPartialResetRequiredIEField, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s00.X2apInternalCompareX2APProtocolIEID(&v.Id, s)
	s00.X2apInternalCompareX2APCriticality(&v.Criticality, s)
	*s = s18.X2apInternalENDCPartialResetRequiredIEValueCompareSemantics(v.Value, *s)
	s.End(f, *s18.X2apInternalENDCPartialResetRequiredIEFieldFieldReplay(v), *s18.X2apInternalENDCPartialResetRequiredIEFieldFieldWithoutReplay(v))
}

// CellActivationResponseAPERValue is the concrete APERValue[CellActivationResponse].
type CellActivationResponseAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         CellActivationResponse
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v CellActivationResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v CellActivationResponseAPERValue) WithoutReplay() CellActivationResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENBConfigurationUpdateAcknowledgeAPERValue is the concrete APERValue[ENBConfigurationUpdateAcknowledge].
type ENBConfigurationUpdateAcknowledgeAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         ENBConfigurationUpdateAcknowledge
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v ENBConfigurationUpdateAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v ENBConfigurationUpdateAcknowledgeAPERValue) WithoutReplay() ENBConfigurationUpdateAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCCellActivationResponseAPERValue is the concrete APERValue[ENDCCellActivationResponse].
type ENDCCellActivationResponseAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         ENDCCellActivationResponse
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v ENDCCellActivationResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v ENDCCellActivationResponseAPERValue) WithoutReplay() ENDCCellActivationResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCConfigurationUpdateAcknowledgeAPERValue is the concrete APERValue[ENDCConfigurationUpdateAcknowledge].
type ENDCConfigurationUpdateAcknowledgeAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         ENDCConfigurationUpdateAcknowledge
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v ENDCConfigurationUpdateAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v ENDCConfigurationUpdateAcknowledgeAPERValue) WithoutReplay() ENDCConfigurationUpdateAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCPartialResetConfirmAPERValue is the concrete APERValue[ENDCPartialResetConfirm].
type ENDCPartialResetConfirmAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         ENDCPartialResetConfirm
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v ENDCPartialResetConfirmAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v ENDCPartialResetConfirmAPERValue) WithoutReplay() ENDCPartialResetConfirmAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCResourceStatusResponseAPERValue is the concrete APERValue[ENDCResourceStatusResponse].
type ENDCResourceStatusResponseAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         ENDCResourceStatusResponse
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v ENDCResourceStatusResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v ENDCResourceStatusResponseAPERValue) WithoutReplay() ENDCResourceStatusResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCX2RemovalResponseAPERValue is the concrete APERValue[ENDCX2RemovalResponse].
type ENDCX2RemovalResponseAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         ENDCX2RemovalResponse
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v ENDCX2RemovalResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v ENDCX2RemovalResponseAPERValue) WithoutReplay() ENDCX2RemovalResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ENDCX2SetupResponseAPERValue is the concrete APERValue[ENDCX2SetupResponse].
type ENDCX2SetupResponseAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         ENDCX2SetupResponse
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v ENDCX2SetupResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v ENDCX2SetupResponseAPERValue) WithoutReplay() ENDCX2SetupResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EUTRANRCellResourceCoordinationResponseAPERValue is the concrete APERValue[EUTRANRCellResourceCoordinationResponse].
type EUTRANRCellResourceCoordinationResponseAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         EUTRANRCellResourceCoordinationResponse
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v EUTRANRCellResourceCoordinationResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v EUTRANRCellResourceCoordinationResponseAPERValue) WithoutReplay() EUTRANRCellResourceCoordinationResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequestAcknowledgeAPERValue is the concrete APERValue[HandoverRequestAcknowledge].
type HandoverRequestAcknowledgeAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         HandoverRequestAcknowledge
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v HandoverRequestAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v HandoverRequestAcknowledgeAPERValue) WithoutReplay() HandoverRequestAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MobilityChangeAcknowledgeAPERValue is the concrete APERValue[MobilityChangeAcknowledge].
type MobilityChangeAcknowledgeAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         MobilityChangeAcknowledge
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v MobilityChangeAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v MobilityChangeAcknowledgeAPERValue) WithoutReplay() MobilityChangeAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetResponseAPERValue is the concrete APERValue[ResetResponse].
type ResetResponseAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         ResetResponse
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v ResetResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v ResetResponseAPERValue) WithoutReplay() ResetResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResourceStatusResponseAPERValue is the concrete APERValue[ResourceStatusResponse].
type ResourceStatusResponseAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         ResourceStatusResponse
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v ResourceStatusResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v ResourceStatusResponseAPERValue) WithoutReplay() ResourceStatusResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RetrieveUEContextResponseAPERValue is the concrete APERValue[RetrieveUEContextResponse].
type RetrieveUEContextResponseAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         RetrieveUEContextResponse
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v RetrieveUEContextResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v RetrieveUEContextResponseAPERValue) WithoutReplay() RetrieveUEContextResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SeNBAdditionRequestAcknowledgeAPERValue is the concrete APERValue[SeNBAdditionRequestAcknowledge].
type SeNBAdditionRequestAcknowledgeAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         SeNBAdditionRequestAcknowledge
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v SeNBAdditionRequestAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v SeNBAdditionRequestAcknowledgeAPERValue) WithoutReplay() SeNBAdditionRequestAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SeNBModificationConfirmAPERValue is the concrete APERValue[SeNBModificationConfirm].
type SeNBModificationConfirmAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         SeNBModificationConfirm
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v SeNBModificationConfirmAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v SeNBModificationConfirmAPERValue) WithoutReplay() SeNBModificationConfirmAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SeNBModificationRequestAcknowledgeAPERValue is the concrete APERValue[SeNBModificationRequestAcknowledge].
type SeNBModificationRequestAcknowledgeAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         SeNBModificationRequestAcknowledge
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v SeNBModificationRequestAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v SeNBModificationRequestAcknowledgeAPERValue) WithoutReplay() SeNBModificationRequestAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SeNBReleaseConfirmAPERValue is the concrete APERValue[SeNBReleaseConfirm].
type SeNBReleaseConfirmAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         SeNBReleaseConfirm
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v SeNBReleaseConfirmAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v SeNBReleaseConfirmAPERValue) WithoutReplay() SeNBReleaseConfirmAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SgNBAdditionRequestAcknowledgeAPERValue is the concrete APERValue[SgNBAdditionRequestAcknowledge].
type SgNBAdditionRequestAcknowledgeAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         SgNBAdditionRequestAcknowledge
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v SgNBAdditionRequestAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v SgNBAdditionRequestAcknowledgeAPERValue) WithoutReplay() SgNBAdditionRequestAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SgNBChangeConfirmAPERValue is the concrete APERValue[SgNBChangeConfirm].
type SgNBChangeConfirmAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         SgNBChangeConfirm
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v SgNBChangeConfirmAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v SgNBChangeConfirmAPERValue) WithoutReplay() SgNBChangeConfirmAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SgNBModificationConfirmAPERValue is the concrete APERValue[SgNBModificationConfirm].
type SgNBModificationConfirmAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         SgNBModificationConfirm
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v SgNBModificationConfirmAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v SgNBModificationConfirmAPERValue) WithoutReplay() SgNBModificationConfirmAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SgNBModificationRequestAcknowledgeAPERValue is the concrete APERValue[SgNBModificationRequestAcknowledge].
type SgNBModificationRequestAcknowledgeAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         SgNBModificationRequestAcknowledge
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v SgNBModificationRequestAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v SgNBModificationRequestAcknowledgeAPERValue) WithoutReplay() SgNBModificationRequestAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SgNBReleaseConfirmAPERValue is the concrete APERValue[SgNBReleaseConfirm].
type SgNBReleaseConfirmAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         SgNBReleaseConfirm
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v SgNBReleaseConfirmAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v SgNBReleaseConfirmAPERValue) WithoutReplay() SgNBReleaseConfirmAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SgNBReleaseRequestAcknowledgeAPERValue is the concrete APERValue[SgNBReleaseRequestAcknowledge].
type SgNBReleaseRequestAcknowledgeAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         SgNBReleaseRequestAcknowledge
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v SgNBReleaseRequestAcknowledgeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v SgNBReleaseRequestAcknowledgeAPERValue) WithoutReplay() SgNBReleaseRequestAcknowledgeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SuccessfulOutcomeAPERValue is the concrete APERValue[SuccessfulOutcome].
type SuccessfulOutcomeAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         SuccessfulOutcome
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v SuccessfulOutcomeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v SuccessfulOutcomeAPERValue) WithoutReplay() SuccessfulOutcomeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityIDMappingResponseAPERValue is the concrete APERValue[UERadioCapabilityIDMappingResponse].
type UERadioCapabilityIDMappingResponseAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         UERadioCapabilityIDMappingResponse
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v UERadioCapabilityIDMappingResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v UERadioCapabilityIDMappingResponseAPERValue) WithoutReplay() UERadioCapabilityIDMappingResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// X2RemovalResponseAPERValue is the concrete APERValue[X2RemovalResponse].
type X2RemovalResponseAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         X2RemovalResponse
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v X2RemovalResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v X2RemovalResponseAPERValue) WithoutReplay() X2RemovalResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// X2SetupResponseAPERValue is the concrete APERValue[X2SetupResponse].
type X2SetupResponseAPERValue struct {
	context       s00.X2apInternalCodecContext
	Value         X2SetupResponse
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v X2SetupResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v X2SetupResponseAPERValue) WithoutReplay() X2SetupResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

type SuccessfulValue struct {
	code                                        s00.ProcedureCode
	received                                    aper.WireSpan
	replay                                      aper.Snapshot
	opaque                                      aper.OpaqueOpenType
	isOpaque                                    bool
	bodyHandoverRequestAcknowledge              *HandoverRequestAcknowledge
	bodyX2SetupResponse                         *X2SetupResponse
	bodyResetResponse                           *ResetResponse
	bodyENBConfigurationUpdateAcknowledge       *ENBConfigurationUpdateAcknowledge
	bodyResourceStatusResponse                  *ResourceStatusResponse
	bodyMobilityChangeAcknowledge               *MobilityChangeAcknowledge
	bodyCellActivationResponse                  *CellActivationResponse
	bodyX2RemovalResponse                       *X2RemovalResponse
	bodySeNBAdditionRequestAcknowledge          *SeNBAdditionRequestAcknowledge
	bodySeNBModificationRequestAcknowledge      *SeNBModificationRequestAcknowledge
	bodySeNBModificationConfirm                 *SeNBModificationConfirm
	bodySeNBReleaseConfirm                      *SeNBReleaseConfirm
	bodyRetrieveUEContextResponse               *RetrieveUEContextResponse
	bodySgNBAdditionRequestAcknowledge          *SgNBAdditionRequestAcknowledge
	bodySgNBModificationRequestAcknowledge      *SgNBModificationRequestAcknowledge
	bodySgNBModificationConfirm                 *SgNBModificationConfirm
	bodySgNBReleaseRequestAcknowledge           *SgNBReleaseRequestAcknowledge
	bodySgNBReleaseConfirm                      *SgNBReleaseConfirm
	bodySgNBChangeConfirm                       *SgNBChangeConfirm
	bodyENDCX2SetupResponse                     *ENDCX2SetupResponse
	bodyENDCConfigurationUpdateAcknowledge      *ENDCConfigurationUpdateAcknowledge
	bodyENDCCellActivationResponse              *ENDCCellActivationResponse
	bodyENDCPartialResetConfirm                 *ENDCPartialResetConfirm
	bodyEUTRANRCellResourceCoordinationResponse *EUTRANRCellResourceCoordinationResponse
	bodyENDCX2RemovalResponse                   *ENDCX2RemovalResponse
	bodyENDCResourceStatusResponse              *ENDCResourceStatusResponse
	bodyUERadioCapabilityIDMappingResponse      *UERadioCapabilityIDMappingResponse
}

// Opaque returns the retained opaque open value of SuccessfulValue and reports whether the opaque alternative is selected.
func (v *SuccessfulValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}

// AsHandoverRequestAcknowledge returns the selected HandoverRequestAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsHandoverRequestAcknowledge() (*HandoverRequestAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(0) || v.bodyHandoverRequestAcknowledge == nil {
		return nil, false
	}
	return v.bodyHandoverRequestAcknowledge, true
}

// AsX2SetupResponse returns the selected X2SetupResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsX2SetupResponse() (*X2SetupResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(6) || v.bodyX2SetupResponse == nil {
		return nil, false
	}
	return v.bodyX2SetupResponse, true
}

// AsResetResponse returns the selected ResetResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsResetResponse() (*ResetResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(7) || v.bodyResetResponse == nil {
		return nil, false
	}
	return v.bodyResetResponse, true
}

// AsENBConfigurationUpdateAcknowledge returns the selected ENBConfigurationUpdateAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsENBConfigurationUpdateAcknowledge() (*ENBConfigurationUpdateAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(8) || v.bodyENBConfigurationUpdateAcknowledge == nil {
		return nil, false
	}
	return v.bodyENBConfigurationUpdateAcknowledge, true
}

// AsResourceStatusResponse returns the selected ResourceStatusResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsResourceStatusResponse() (*ResourceStatusResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(9) || v.bodyResourceStatusResponse == nil {
		return nil, false
	}
	return v.bodyResourceStatusResponse, true
}

// AsMobilityChangeAcknowledge returns the selected MobilityChangeAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsMobilityChangeAcknowledge() (*MobilityChangeAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(12) || v.bodyMobilityChangeAcknowledge == nil {
		return nil, false
	}
	return v.bodyMobilityChangeAcknowledge, true
}

// AsCellActivationResponse returns the selected CellActivationResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsCellActivationResponse() (*CellActivationResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(15) || v.bodyCellActivationResponse == nil {
		return nil, false
	}
	return v.bodyCellActivationResponse, true
}

// AsX2RemovalResponse returns the selected X2RemovalResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsX2RemovalResponse() (*X2RemovalResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(18) || v.bodyX2RemovalResponse == nil {
		return nil, false
	}
	return v.bodyX2RemovalResponse, true
}

// AsSeNBAdditionRequestAcknowledge returns the selected SeNBAdditionRequestAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsSeNBAdditionRequestAcknowledge() (*SeNBAdditionRequestAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(19) || v.bodySeNBAdditionRequestAcknowledge == nil {
		return nil, false
	}
	return v.bodySeNBAdditionRequestAcknowledge, true
}

// AsSeNBModificationRequestAcknowledge returns the selected SeNBModificationRequestAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsSeNBModificationRequestAcknowledge() (*SeNBModificationRequestAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(21) || v.bodySeNBModificationRequestAcknowledge == nil {
		return nil, false
	}
	return v.bodySeNBModificationRequestAcknowledge, true
}

// AsSeNBModificationConfirm returns the selected SeNBModificationConfirm value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsSeNBModificationConfirm() (*SeNBModificationConfirm, bool) {
	if v == nil || v.code != s00.ProcedureCode(22) || v.bodySeNBModificationConfirm == nil {
		return nil, false
	}
	return v.bodySeNBModificationConfirm, true
}

// AsSeNBReleaseConfirm returns the selected SeNBReleaseConfirm value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsSeNBReleaseConfirm() (*SeNBReleaseConfirm, bool) {
	if v == nil || v.code != s00.ProcedureCode(24) || v.bodySeNBReleaseConfirm == nil {
		return nil, false
	}
	return v.bodySeNBReleaseConfirm, true
}

// AsRetrieveUEContextResponse returns the selected RetrieveUEContextResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsRetrieveUEContextResponse() (*RetrieveUEContextResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(26) || v.bodyRetrieveUEContextResponse == nil {
		return nil, false
	}
	return v.bodyRetrieveUEContextResponse, true
}

// AsSgNBAdditionRequestAcknowledge returns the selected SgNBAdditionRequestAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsSgNBAdditionRequestAcknowledge() (*SgNBAdditionRequestAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(27) || v.bodySgNBAdditionRequestAcknowledge == nil {
		return nil, false
	}
	return v.bodySgNBAdditionRequestAcknowledge, true
}

// AsSgNBModificationRequestAcknowledge returns the selected SgNBModificationRequestAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsSgNBModificationRequestAcknowledge() (*SgNBModificationRequestAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(29) || v.bodySgNBModificationRequestAcknowledge == nil {
		return nil, false
	}
	return v.bodySgNBModificationRequestAcknowledge, true
}

// AsSgNBModificationConfirm returns the selected SgNBModificationConfirm value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsSgNBModificationConfirm() (*SgNBModificationConfirm, bool) {
	if v == nil || v.code != s00.ProcedureCode(30) || v.bodySgNBModificationConfirm == nil {
		return nil, false
	}
	return v.bodySgNBModificationConfirm, true
}

// AsSgNBReleaseRequestAcknowledge returns the selected SgNBReleaseRequestAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsSgNBReleaseRequestAcknowledge() (*SgNBReleaseRequestAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(31) || v.bodySgNBReleaseRequestAcknowledge == nil {
		return nil, false
	}
	return v.bodySgNBReleaseRequestAcknowledge, true
}

// AsSgNBReleaseConfirm returns the selected SgNBReleaseConfirm value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsSgNBReleaseConfirm() (*SgNBReleaseConfirm, bool) {
	if v == nil || v.code != s00.ProcedureCode(32) || v.bodySgNBReleaseConfirm == nil {
		return nil, false
	}
	return v.bodySgNBReleaseConfirm, true
}

// AsSgNBChangeConfirm returns the selected SgNBChangeConfirm value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsSgNBChangeConfirm() (*SgNBChangeConfirm, bool) {
	if v == nil || v.code != s00.ProcedureCode(34) || v.bodySgNBChangeConfirm == nil {
		return nil, false
	}
	return v.bodySgNBChangeConfirm, true
}

// AsENDCX2SetupResponse returns the selected ENDCX2SetupResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsENDCX2SetupResponse() (*ENDCX2SetupResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(36) || v.bodyENDCX2SetupResponse == nil {
		return nil, false
	}
	return v.bodyENDCX2SetupResponse, true
}

// AsENDCConfigurationUpdateAcknowledge returns the selected ENDCConfigurationUpdateAcknowledge value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsENDCConfigurationUpdateAcknowledge() (*ENDCConfigurationUpdateAcknowledge, bool) {
	if v == nil || v.code != s00.ProcedureCode(37) || v.bodyENDCConfigurationUpdateAcknowledge == nil {
		return nil, false
	}
	return v.bodyENDCConfigurationUpdateAcknowledge, true
}

// AsENDCCellActivationResponse returns the selected ENDCCellActivationResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsENDCCellActivationResponse() (*ENDCCellActivationResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(39) || v.bodyENDCCellActivationResponse == nil {
		return nil, false
	}
	return v.bodyENDCCellActivationResponse, true
}

// AsENDCPartialResetConfirm returns the selected ENDCPartialResetConfirm value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsENDCPartialResetConfirm() (*ENDCPartialResetConfirm, bool) {
	if v == nil || v.code != s00.ProcedureCode(40) || v.bodyENDCPartialResetConfirm == nil {
		return nil, false
	}
	return v.bodyENDCPartialResetConfirm, true
}

// AsEUTRANRCellResourceCoordinationResponse returns the selected EUTRANRCellResourceCoordinationResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsEUTRANRCellResourceCoordinationResponse() (*EUTRANRCellResourceCoordinationResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(41) || v.bodyEUTRANRCellResourceCoordinationResponse == nil {
		return nil, false
	}
	return v.bodyEUTRANRCellResourceCoordinationResponse, true
}

// AsENDCX2RemovalResponse returns the selected ENDCX2RemovalResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsENDCX2RemovalResponse() (*ENDCX2RemovalResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(43) || v.bodyENDCX2RemovalResponse == nil {
		return nil, false
	}
	return v.bodyENDCX2RemovalResponse, true
}

// AsENDCResourceStatusResponse returns the selected ENDCResourceStatusResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsENDCResourceStatusResponse() (*ENDCResourceStatusResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(54) || v.bodyENDCResourceStatusResponse == nil {
		return nil, false
	}
	return v.bodyENDCResourceStatusResponse, true
}

// AsUERadioCapabilityIDMappingResponse returns the selected UERadioCapabilityIDMappingResponse value of SuccessfulValue and reports whether that alternative is active.
func (v *SuccessfulValue) AsUERadioCapabilityIDMappingResponse() (*UERadioCapabilityIDMappingResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(56) || v.bodyUERadioCapabilityIDMappingResponse == nil {
		return nil, false
	}
	return v.bodyUERadioCapabilityIDMappingResponse, true
}
func X2apInternalDecodeSuccessfulValue(code s00.ProcedureCode, raw aper.OpaqueOpenType) (SuccessfulValue, error) {
	v := SuccessfulValue{code: code}
	switch code {
	case s00.ProcedureCode(0):
		var body HandoverRequestAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalHandoverRequestAcknowledgeUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.HandoverRequestAcknowledge: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverRequestAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyHandoverRequestAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(6):
		var body X2SetupResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalX2SetupResponseUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.X2SetupResponse: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "X2SetupResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyX2SetupResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(7):
		var body ResetResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalResetResponseUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.ResetResponse: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ResetResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyResetResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(8):
		var body ENBConfigurationUpdateAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalENBConfigurationUpdateAcknowledgeUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.ENBConfigurationUpdateAcknowledge: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBConfigurationUpdateAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyENBConfigurationUpdateAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(9):
		var body ResourceStatusResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalResourceStatusResponseUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.ResourceStatusResponse: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ResourceStatusResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyResourceStatusResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(12):
		var body MobilityChangeAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalMobilityChangeAcknowledgeUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.MobilityChangeAcknowledge: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "MobilityChangeAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyMobilityChangeAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(15):
		var body CellActivationResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalCellActivationResponseUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.CellActivationResponse: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CellActivationResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyCellActivationResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(18):
		var body X2RemovalResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalX2RemovalResponseUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.X2RemovalResponse: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "X2RemovalResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyX2RemovalResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(19):
		var body SeNBAdditionRequestAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalSeNBAdditionRequestAcknowledgeUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.SeNBAdditionRequestAcknowledge: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SeNBAdditionRequestAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodySeNBAdditionRequestAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(21):
		var body SeNBModificationRequestAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalSeNBModificationRequestAcknowledgeUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.SeNBModificationRequestAcknowledge: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SeNBModificationRequestAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodySeNBModificationRequestAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(22):
		var body SeNBModificationConfirm
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalSeNBModificationConfirmUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.SeNBModificationConfirm: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SeNBModificationConfirm")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodySeNBModificationConfirm = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(24):
		var body SeNBReleaseConfirm
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalSeNBReleaseConfirmUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.SeNBReleaseConfirm: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SeNBReleaseConfirm")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodySeNBReleaseConfirm = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(26):
		var body RetrieveUEContextResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalRetrieveUEContextResponseUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.RetrieveUEContextResponse: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "RetrieveUEContextResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyRetrieveUEContextResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(27):
		var body SgNBAdditionRequestAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalSgNBAdditionRequestAcknowledgeUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.SgNBAdditionRequestAcknowledge: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SgNBAdditionRequestAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodySgNBAdditionRequestAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(29):
		var body SgNBModificationRequestAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalSgNBModificationRequestAcknowledgeUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.SgNBModificationRequestAcknowledge: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SgNBModificationRequestAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodySgNBModificationRequestAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(30):
		var body SgNBModificationConfirm
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalSgNBModificationConfirmUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.SgNBModificationConfirm: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SgNBModificationConfirm")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodySgNBModificationConfirm = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(31):
		var body SgNBReleaseRequestAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalSgNBReleaseRequestAcknowledgeUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.SgNBReleaseRequestAcknowledge: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SgNBReleaseRequestAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodySgNBReleaseRequestAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(32):
		var body SgNBReleaseConfirm
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalSgNBReleaseConfirmUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.SgNBReleaseConfirm: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SgNBReleaseConfirm")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodySgNBReleaseConfirm = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(34):
		var body SgNBChangeConfirm
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalSgNBChangeConfirmUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.SgNBChangeConfirm: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SgNBChangeConfirm")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodySgNBChangeConfirm = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(36):
		var body ENDCX2SetupResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalENDCX2SetupResponseUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.ENDCX2SetupResponse: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENDCX2SetupResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyENDCX2SetupResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(37):
		var body ENDCConfigurationUpdateAcknowledge
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalENDCConfigurationUpdateAcknowledgeUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.ENDCConfigurationUpdateAcknowledge: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENDCConfigurationUpdateAcknowledge")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyENDCConfigurationUpdateAcknowledge = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(39):
		var body ENDCCellActivationResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalENDCCellActivationResponseUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.ENDCCellActivationResponse: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENDCCellActivationResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyENDCCellActivationResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(40):
		var body ENDCPartialResetConfirm
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalENDCPartialResetConfirmUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.ENDCPartialResetConfirm: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENDCPartialResetConfirm")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyENDCPartialResetConfirm = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(41):
		var body EUTRANRCellResourceCoordinationResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalEUTRANRCellResourceCoordinationResponseUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.EUTRANRCellResourceCoordinationResponse: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "EUTRANRCellResourceCoordinationResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyEUTRANRCellResourceCoordinationResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(43):
		var body ENDCX2RemovalResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalENDCX2RemovalResponseUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.ENDCX2RemovalResponse: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENDCX2RemovalResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyENDCX2RemovalResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(54):
		var body ENDCResourceStatusResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalENDCResourceStatusResponseUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.ENDCResourceStatusResponse: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENDCResourceStatusResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyENDCResourceStatusResponse = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(56):
		var body UERadioCapabilityIDMappingResponse
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return SuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := X2apInternalUERadioCapabilityIDMappingResponseUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("SuccessfulMessage.value.UERadioCapabilityIDMappingResponse: %w", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UERadioCapabilityIDMappingResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.CaptureContentLocation()
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyUERadioCapabilityIDMappingResponse = &body
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
func X2apInternalSuccessfulValueEncode(v SuccessfulValue) ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return X2apInternalSuccessfulValueEncodeFresh(v, false, budget)
}
func X2apInternalSuccessfulValueEncodeFresh(v SuccessfulValue, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if v.isOpaque {
		return v.opaque.EncodeBytes(budget)
	}
	switch v.code {
	case s00.ProcedureCode(0):
		if v.bodyHandoverRequestAcknowledge == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing HandoverRequestAcknowledge")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalHandoverRequestAcknowledgeMarshalAPERBudget(v.bodyHandoverRequestAcknowledge, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(6):
		if v.bodyX2SetupResponse == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing X2SetupResponse")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalX2SetupResponseMarshalAPERBudget(v.bodyX2SetupResponse, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(7):
		if v.bodyResetResponse == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing ResetResponse")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalResetResponseMarshalAPERBudget(v.bodyResetResponse, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(8):
		if v.bodyENBConfigurationUpdateAcknowledge == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing ENBConfigurationUpdateAcknowledge")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERBudget(v.bodyENBConfigurationUpdateAcknowledge, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(9):
		if v.bodyResourceStatusResponse == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing ResourceStatusResponse")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalResourceStatusResponseMarshalAPERBudget(v.bodyResourceStatusResponse, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(12):
		if v.bodyMobilityChangeAcknowledge == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing MobilityChangeAcknowledge")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalMobilityChangeAcknowledgeMarshalAPERBudget(v.bodyMobilityChangeAcknowledge, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(15):
		if v.bodyCellActivationResponse == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing CellActivationResponse")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalCellActivationResponseMarshalAPERBudget(v.bodyCellActivationResponse, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(18):
		if v.bodyX2RemovalResponse == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing X2RemovalResponse")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalX2RemovalResponseMarshalAPERBudget(v.bodyX2RemovalResponse, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(19):
		if v.bodySeNBAdditionRequestAcknowledge == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing SeNBAdditionRequestAcknowledge")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERBudget(v.bodySeNBAdditionRequestAcknowledge, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(21):
		if v.bodySeNBModificationRequestAcknowledge == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing SeNBModificationRequestAcknowledge")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERBudget(v.bodySeNBModificationRequestAcknowledge, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(22):
		if v.bodySeNBModificationConfirm == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing SeNBModificationConfirm")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalSeNBModificationConfirmMarshalAPERBudget(v.bodySeNBModificationConfirm, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(24):
		if v.bodySeNBReleaseConfirm == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing SeNBReleaseConfirm")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalSeNBReleaseConfirmMarshalAPERBudget(v.bodySeNBReleaseConfirm, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(26):
		if v.bodyRetrieveUEContextResponse == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing RetrieveUEContextResponse")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalRetrieveUEContextResponseMarshalAPERBudget(v.bodyRetrieveUEContextResponse, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(27):
		if v.bodySgNBAdditionRequestAcknowledge == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing SgNBAdditionRequestAcknowledge")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERBudget(v.bodySgNBAdditionRequestAcknowledge, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(29):
		if v.bodySgNBModificationRequestAcknowledge == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing SgNBModificationRequestAcknowledge")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERBudget(v.bodySgNBModificationRequestAcknowledge, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(30):
		if v.bodySgNBModificationConfirm == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing SgNBModificationConfirm")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalSgNBModificationConfirmMarshalAPERBudget(v.bodySgNBModificationConfirm, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(31):
		if v.bodySgNBReleaseRequestAcknowledge == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing SgNBReleaseRequestAcknowledge")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERBudget(v.bodySgNBReleaseRequestAcknowledge, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(32):
		if v.bodySgNBReleaseConfirm == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing SgNBReleaseConfirm")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalSgNBReleaseConfirmMarshalAPERBudget(v.bodySgNBReleaseConfirm, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(34):
		if v.bodySgNBChangeConfirm == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing SgNBChangeConfirm")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalSgNBChangeConfirmMarshalAPERBudget(v.bodySgNBChangeConfirm, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(36):
		if v.bodyENDCX2SetupResponse == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing ENDCX2SetupResponse")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalENDCX2SetupResponseMarshalAPERBudget(v.bodyENDCX2SetupResponse, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(37):
		if v.bodyENDCConfigurationUpdateAcknowledge == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing ENDCConfigurationUpdateAcknowledge")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERBudget(v.bodyENDCConfigurationUpdateAcknowledge, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(39):
		if v.bodyENDCCellActivationResponse == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing ENDCCellActivationResponse")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalENDCCellActivationResponseMarshalAPERBudget(v.bodyENDCCellActivationResponse, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(40):
		if v.bodyENDCPartialResetConfirm == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing ENDCPartialResetConfirm")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalENDCPartialResetConfirmMarshalAPERBudget(v.bodyENDCPartialResetConfirm, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(41):
		if v.bodyEUTRANRCellResourceCoordinationResponse == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing EUTRANRCellResourceCoordinationResponse")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERBudget(v.bodyEUTRANRCellResourceCoordinationResponse, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(43):
		if v.bodyENDCX2RemovalResponse == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing ENDCX2RemovalResponse")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalENDCX2RemovalResponseMarshalAPERBudget(v.bodyENDCX2RemovalResponse, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(54):
		if v.bodyENDCResourceStatusResponse == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing ENDCResourceStatusResponse")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalENDCResourceStatusResponseMarshalAPERBudget(v.bodyENDCResourceStatusResponse, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProcedureCode(56):
		if v.bodyUERadioCapabilityIDMappingResponse == nil {
			return nil, fmt.Errorf("SuccessfulValue: missing UERadioCapabilityIDMappingResponse")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return v.received.EncodeBytes(budget)
		}
		candidate, err := X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERBudget(v.bodyUERadioCapabilityIDMappingResponse, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("SuccessfulValue: unknown code %d without opaque content", v.code)
	}
}
func NewOpaqueSuccessfulOutcome(code s00.ProcedureCode, criticality s00.Criticality, data []byte) (SuccessfulOutcome, error) {
	switch code {
	case s00.ProcedureCode(0):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-handoverPreparation requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(6):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-x2Setup requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(7):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-reset requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(8):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-eNBConfigurationUpdate requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(9):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-resourceStatusReportingInitiation requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(12):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-mobilitySettingsChange requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(15):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-cellActivation requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(18):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-x2Removal requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(19):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-seNBAdditionPreparation requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(21):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-meNBinitiatedSeNBModificationPreparation requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(22):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-seNBinitiatedSeNBModification requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(24):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-seNBinitiatedSeNBRelease requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(26):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-retrieveUEContext requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(27):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-sgNBAdditionPreparation requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(29):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-meNBinitiatedSgNBModificationPreparation requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(30):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-sgNBinitiatedSgNBModification requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(31):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-meNBinitiatedSgNBRelease requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(32):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-sgNBinitiatedSgNBRelease requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(34):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-sgNBChange requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(36):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-endcX2Setup requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(37):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-endcConfigurationUpdate requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(39):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-endcCellActivation requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(40):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-endcPartialReset requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(41):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-eUTRANRCellResourceCoordination requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(43):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-endcX2Removal requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(54):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-endcresourceStatusReportingInitiation requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(56):
		return SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-UERadioCapabilityIDMapping requires its typed binding"), "OpaqueSuccessfulOutcome")
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
	if _, err := X2apInternalSuccessfulOutcomeMarshalAPERBudget(&message, budget, false); err != nil {
		return SuccessfulOutcome{}, aper.OperationError(err, "OpaqueSuccessfulOutcome")
	}
	return message, aper.OperationError(nil, "OpaqueSuccessfulOutcome")
}
func X2apInternalCaptureX2APCellActivationResponse(v *CellActivationResponse, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s13.X2apInternalCellActivationResponseIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APCellActivationResponse(v *CellActivationResponse, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s13.X2apInternalCellActivationResponseIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APENBConfigurationUpdateAcknowledge(v *ENBConfigurationUpdateAcknowledge, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s07.X2apInternalENBConfigurationUpdateAcknowledgeIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APENBConfigurationUpdateAcknowledge(v *ENBConfigurationUpdateAcknowledge, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s07.X2apInternalENBConfigurationUpdateAcknowledgeIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APENDCCellActivationResponse(v *ENDCCellActivationResponse, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s13.X2apInternalENDCCellActivationResponseIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APENDCCellActivationResponse(v *ENDCCellActivationResponse, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s13.X2apInternalENDCCellActivationResponseIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APENDCConfigurationUpdateAcknowledge(v *ENDCConfigurationUpdateAcknowledge, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s18.X2apInternalENDCConfigurationUpdateAcknowledgeIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APENDCConfigurationUpdateAcknowledge(v *ENDCConfigurationUpdateAcknowledge, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s18.X2apInternalENDCConfigurationUpdateAcknowledgeIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APENDCPartialResetConfirm(v *ENDCPartialResetConfirm, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s18.X2apInternalENDCPartialResetConfirmIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APENDCPartialResetConfirm(v *ENDCPartialResetConfirm, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s18.X2apInternalENDCPartialResetConfirmIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APENDCResourceStatusResponse(v *ENDCResourceStatusResponse, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s07.X2apInternalENDCResourceStatusResponseIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APENDCResourceStatusResponse(v *ENDCResourceStatusResponse, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s07.X2apInternalENDCResourceStatusResponseIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APENDCX2RemovalResponse(v *ENDCX2RemovalResponse, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s07.X2apInternalENDCX2RemovalResponseIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APENDCX2RemovalResponse(v *ENDCX2RemovalResponse, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s07.X2apInternalENDCX2RemovalResponseIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APENDCX2SetupResponse(v *ENDCX2SetupResponse, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s18.X2apInternalENDCX2SetupResponseIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APENDCX2SetupResponse(v *ENDCX2SetupResponse, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s18.X2apInternalENDCX2SetupResponseIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APEUTRANRCellResourceCoordinationResponse(v *EUTRANRCellResourceCoordinationResponse, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s16.X2apInternalEUTRANRCellResourceCoordinationResponseIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APEUTRANRCellResourceCoordinationResponse(v *EUTRANRCellResourceCoordinationResponse, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s16.X2apInternalEUTRANRCellResourceCoordinationResponseIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APHandoverRequestAcknowledge(v *HandoverRequestAcknowledge, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s14.X2apInternalHandoverRequestAcknowledgeIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APHandoverRequestAcknowledge(v *HandoverRequestAcknowledge, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s14.X2apInternalHandoverRequestAcknowledgeIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APMobilityChangeAcknowledge(v *MobilityChangeAcknowledge, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s08.X2apInternalMobilityChangeAcknowledgeIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APMobilityChangeAcknowledge(v *MobilityChangeAcknowledge, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s08.X2apInternalMobilityChangeAcknowledgeIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APResetResponse(v *ResetResponse, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s08.X2apInternalResetResponseIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APResetResponse(v *ResetResponse, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s08.X2apInternalResetResponseIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APResourceStatusResponse(v *ResourceStatusResponse, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s16.X2apInternalResourceStatusResponseIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APResourceStatusResponse(v *ResourceStatusResponse, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s16.X2apInternalResourceStatusResponseIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APRetrieveUEContextResponse(v *RetrieveUEContextResponse, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s17.X2apInternalRetrieveUEContextResponseIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APRetrieveUEContextResponse(v *RetrieveUEContextResponse, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s17.X2apInternalRetrieveUEContextResponseIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APSeNBAdditionRequestAcknowledge(v *SeNBAdditionRequestAcknowledge, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s15.X2apInternalSeNBAdditionRequestAcknowledgeIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APSeNBAdditionRequestAcknowledge(v *SeNBAdditionRequestAcknowledge, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s15.X2apInternalSeNBAdditionRequestAcknowledgeIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APSeNBModificationConfirm(v *SeNBModificationConfirm, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s12.X2apInternalSeNBModificationConfirmIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APSeNBModificationConfirm(v *SeNBModificationConfirm, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s12.X2apInternalSeNBModificationConfirmIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APSeNBModificationRequestAcknowledge(v *SeNBModificationRequestAcknowledge, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s15.X2apInternalSeNBModificationRequestAcknowledgeIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APSeNBModificationRequestAcknowledge(v *SeNBModificationRequestAcknowledge, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s15.X2apInternalSeNBModificationRequestAcknowledgeIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APSeNBReleaseConfirm(v *SeNBReleaseConfirm, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s15.X2apInternalSeNBReleaseConfirmIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APSeNBReleaseConfirm(v *SeNBReleaseConfirm, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s15.X2apInternalSeNBReleaseConfirmIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APSgNBAdditionRequestAcknowledge(v *SgNBAdditionRequestAcknowledge, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s15.X2apInternalSgNBAdditionRequestAcknowledgeIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APSgNBAdditionRequestAcknowledge(v *SgNBAdditionRequestAcknowledge, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s15.X2apInternalSgNBAdditionRequestAcknowledgeIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APSgNBChangeConfirm(v *SgNBChangeConfirm, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s15.X2apInternalSgNBChangeConfirmIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APSgNBChangeConfirm(v *SgNBChangeConfirm, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s15.X2apInternalSgNBChangeConfirmIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APSgNBModificationConfirm(v *SgNBModificationConfirm, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s15.X2apInternalSgNBModificationConfirmIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APSgNBModificationConfirm(v *SgNBModificationConfirm, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s15.X2apInternalSgNBModificationConfirmIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APSgNBModificationRequestAcknowledge(v *SgNBModificationRequestAcknowledge, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s17.X2apInternalSgNBModificationRequestAcknowledgeIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APSgNBModificationRequestAcknowledge(v *SgNBModificationRequestAcknowledge, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s17.X2apInternalSgNBModificationRequestAcknowledgeIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APSgNBReleaseConfirm(v *SgNBReleaseConfirm, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s15.X2apInternalSgNBReleaseConfirmIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APSgNBReleaseConfirm(v *SgNBReleaseConfirm, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s15.X2apInternalSgNBReleaseConfirmIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APSgNBReleaseRequestAcknowledge(v *SgNBReleaseRequestAcknowledge, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s17.X2apInternalSgNBReleaseRequestAcknowledgeIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APSgNBReleaseRequestAcknowledge(v *SgNBReleaseRequestAcknowledge, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s17.X2apInternalSgNBReleaseRequestAcknowledgeIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APSuccessfulOutcome(v *SuccessfulOutcome, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s00.X2apInternalCaptureX2APProcedureCode(&v.ProcedureCode, s)
	s00.X2apInternalCaptureX2APCriticality(&v.Criticality, s)
	X2apInternalCaptureX2APSuccessfulValue(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APSuccessfulOutcome(v *SuccessfulOutcome, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s00.X2apInternalCompareX2APProcedureCode(&v.ProcedureCode, s)
	s00.X2apInternalCompareX2APCriticality(&v.Criticality, s)
	X2apInternalCompareX2APSuccessfulValue(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APSuccessfulValue(v *SuccessfulValue, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	if !v.isOpaque {
		s.Open(v.received)
	}
	s00.X2apInternalCaptureX2APProcedureCode(&v.code, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.code {
		case s00.ProcedureCode(0):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverRequestAcknowledge == nil)
				if v.bodyHandoverRequestAcknowledge != nil {
					X2apInternalCaptureX2APHandoverRequestAcknowledge(v.bodyHandoverRequestAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyX2SetupResponse == nil)
				if v.bodyX2SetupResponse != nil {
					X2apInternalCaptureX2APX2SetupResponse(v.bodyX2SetupResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyResetResponse == nil)
				if v.bodyResetResponse != nil {
					X2apInternalCaptureX2APResetResponse(v.bodyResetResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(8):
			{
				f := s.Begin()
				s.Bool(v.bodyENBConfigurationUpdateAcknowledge == nil)
				if v.bodyENBConfigurationUpdateAcknowledge != nil {
					X2apInternalCaptureX2APENBConfigurationUpdateAcknowledge(v.bodyENBConfigurationUpdateAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyResourceStatusResponse == nil)
				if v.bodyResourceStatusResponse != nil {
					X2apInternalCaptureX2APResourceStatusResponse(v.bodyResourceStatusResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(12):
			{
				f := s.Begin()
				s.Bool(v.bodyMobilityChangeAcknowledge == nil)
				if v.bodyMobilityChangeAcknowledge != nil {
					X2apInternalCaptureX2APMobilityChangeAcknowledge(v.bodyMobilityChangeAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(15):
			{
				f := s.Begin()
				s.Bool(v.bodyCellActivationResponse == nil)
				if v.bodyCellActivationResponse != nil {
					X2apInternalCaptureX2APCellActivationResponse(v.bodyCellActivationResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(18):
			{
				f := s.Begin()
				s.Bool(v.bodyX2RemovalResponse == nil)
				if v.bodyX2RemovalResponse != nil {
					X2apInternalCaptureX2APX2RemovalResponse(v.bodyX2RemovalResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(19):
			{
				f := s.Begin()
				s.Bool(v.bodySeNBAdditionRequestAcknowledge == nil)
				if v.bodySeNBAdditionRequestAcknowledge != nil {
					X2apInternalCaptureX2APSeNBAdditionRequestAcknowledge(v.bodySeNBAdditionRequestAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodySeNBModificationRequestAcknowledge == nil)
				if v.bodySeNBModificationRequestAcknowledge != nil {
					X2apInternalCaptureX2APSeNBModificationRequestAcknowledge(v.bodySeNBModificationRequestAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(22):
			{
				f := s.Begin()
				s.Bool(v.bodySeNBModificationConfirm == nil)
				if v.bodySeNBModificationConfirm != nil {
					X2apInternalCaptureX2APSeNBModificationConfirm(v.bodySeNBModificationConfirm, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(24):
			{
				f := s.Begin()
				s.Bool(v.bodySeNBReleaseConfirm == nil)
				if v.bodySeNBReleaseConfirm != nil {
					X2apInternalCaptureX2APSeNBReleaseConfirm(v.bodySeNBReleaseConfirm, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(26):
			{
				f := s.Begin()
				s.Bool(v.bodyRetrieveUEContextResponse == nil)
				if v.bodyRetrieveUEContextResponse != nil {
					X2apInternalCaptureX2APRetrieveUEContextResponse(v.bodyRetrieveUEContextResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(27):
			{
				f := s.Begin()
				s.Bool(v.bodySgNBAdditionRequestAcknowledge == nil)
				if v.bodySgNBAdditionRequestAcknowledge != nil {
					X2apInternalCaptureX2APSgNBAdditionRequestAcknowledge(v.bodySgNBAdditionRequestAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(29):
			{
				f := s.Begin()
				s.Bool(v.bodySgNBModificationRequestAcknowledge == nil)
				if v.bodySgNBModificationRequestAcknowledge != nil {
					X2apInternalCaptureX2APSgNBModificationRequestAcknowledge(v.bodySgNBModificationRequestAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(30):
			{
				f := s.Begin()
				s.Bool(v.bodySgNBModificationConfirm == nil)
				if v.bodySgNBModificationConfirm != nil {
					X2apInternalCaptureX2APSgNBModificationConfirm(v.bodySgNBModificationConfirm, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(31):
			{
				f := s.Begin()
				s.Bool(v.bodySgNBReleaseRequestAcknowledge == nil)
				if v.bodySgNBReleaseRequestAcknowledge != nil {
					X2apInternalCaptureX2APSgNBReleaseRequestAcknowledge(v.bodySgNBReleaseRequestAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(32):
			{
				f := s.Begin()
				s.Bool(v.bodySgNBReleaseConfirm == nil)
				if v.bodySgNBReleaseConfirm != nil {
					X2apInternalCaptureX2APSgNBReleaseConfirm(v.bodySgNBReleaseConfirm, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(34):
			{
				f := s.Begin()
				s.Bool(v.bodySgNBChangeConfirm == nil)
				if v.bodySgNBChangeConfirm != nil {
					X2apInternalCaptureX2APSgNBChangeConfirm(v.bodySgNBChangeConfirm, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(36):
			{
				f := s.Begin()
				s.Bool(v.bodyENDCX2SetupResponse == nil)
				if v.bodyENDCX2SetupResponse != nil {
					X2apInternalCaptureX2APENDCX2SetupResponse(v.bodyENDCX2SetupResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(37):
			{
				f := s.Begin()
				s.Bool(v.bodyENDCConfigurationUpdateAcknowledge == nil)
				if v.bodyENDCConfigurationUpdateAcknowledge != nil {
					X2apInternalCaptureX2APENDCConfigurationUpdateAcknowledge(v.bodyENDCConfigurationUpdateAcknowledge, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(39):
			{
				f := s.Begin()
				s.Bool(v.bodyENDCCellActivationResponse == nil)
				if v.bodyENDCCellActivationResponse != nil {
					X2apInternalCaptureX2APENDCCellActivationResponse(v.bodyENDCCellActivationResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(40):
			{
				f := s.Begin()
				s.Bool(v.bodyENDCPartialResetConfirm == nil)
				if v.bodyENDCPartialResetConfirm != nil {
					X2apInternalCaptureX2APENDCPartialResetConfirm(v.bodyENDCPartialResetConfirm, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(41):
			{
				f := s.Begin()
				s.Bool(v.bodyEUTRANRCellResourceCoordinationResponse == nil)
				if v.bodyEUTRANRCellResourceCoordinationResponse != nil {
					X2apInternalCaptureX2APEUTRANRCellResourceCoordinationResponse(v.bodyEUTRANRCellResourceCoordinationResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(43):
			{
				f := s.Begin()
				s.Bool(v.bodyENDCX2RemovalResponse == nil)
				if v.bodyENDCX2RemovalResponse != nil {
					X2apInternalCaptureX2APENDCX2RemovalResponse(v.bodyENDCX2RemovalResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(54):
			{
				f := s.Begin()
				s.Bool(v.bodyENDCResourceStatusResponse == nil)
				if v.bodyENDCResourceStatusResponse != nil {
					X2apInternalCaptureX2APENDCResourceStatusResponse(v.bodyENDCResourceStatusResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(56):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityIDMappingResponse == nil)
				if v.bodyUERadioCapabilityIDMappingResponse != nil {
					X2apInternalCaptureX2APUERadioCapabilityIDMappingResponse(v.bodyUERadioCapabilityIDMappingResponse, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
}
func X2apInternalSuccessfulValueCaptureSemantics(v SuccessfulValue, s aper.SemanticCapture) SuccessfulValue {
	X2apInternalCaptureX2APSuccessfulValue(&v, &s)
	return v
}
func X2apInternalCompareX2APSuccessfulValue(v *SuccessfulValue, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	if !v.isOpaque {
		s.Open(v.received)
	}
	s00.X2apInternalCompareX2APProcedureCode(&v.code, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.code {
		case s00.ProcedureCode(0):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverRequestAcknowledge == nil)
				if v.bodyHandoverRequestAcknowledge != nil {
					X2apInternalCompareX2APHandoverRequestAcknowledge(v.bodyHandoverRequestAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyX2SetupResponse == nil)
				if v.bodyX2SetupResponse != nil {
					X2apInternalCompareX2APX2SetupResponse(v.bodyX2SetupResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyResetResponse == nil)
				if v.bodyResetResponse != nil {
					X2apInternalCompareX2APResetResponse(v.bodyResetResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(8):
			{
				f := s.Begin()
				s.Bool(v.bodyENBConfigurationUpdateAcknowledge == nil)
				if v.bodyENBConfigurationUpdateAcknowledge != nil {
					X2apInternalCompareX2APENBConfigurationUpdateAcknowledge(v.bodyENBConfigurationUpdateAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyResourceStatusResponse == nil)
				if v.bodyResourceStatusResponse != nil {
					X2apInternalCompareX2APResourceStatusResponse(v.bodyResourceStatusResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(12):
			{
				f := s.Begin()
				s.Bool(v.bodyMobilityChangeAcknowledge == nil)
				if v.bodyMobilityChangeAcknowledge != nil {
					X2apInternalCompareX2APMobilityChangeAcknowledge(v.bodyMobilityChangeAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(15):
			{
				f := s.Begin()
				s.Bool(v.bodyCellActivationResponse == nil)
				if v.bodyCellActivationResponse != nil {
					X2apInternalCompareX2APCellActivationResponse(v.bodyCellActivationResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(18):
			{
				f := s.Begin()
				s.Bool(v.bodyX2RemovalResponse == nil)
				if v.bodyX2RemovalResponse != nil {
					X2apInternalCompareX2APX2RemovalResponse(v.bodyX2RemovalResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(19):
			{
				f := s.Begin()
				s.Bool(v.bodySeNBAdditionRequestAcknowledge == nil)
				if v.bodySeNBAdditionRequestAcknowledge != nil {
					X2apInternalCompareX2APSeNBAdditionRequestAcknowledge(v.bodySeNBAdditionRequestAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodySeNBModificationRequestAcknowledge == nil)
				if v.bodySeNBModificationRequestAcknowledge != nil {
					X2apInternalCompareX2APSeNBModificationRequestAcknowledge(v.bodySeNBModificationRequestAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(22):
			{
				f := s.Begin()
				s.Bool(v.bodySeNBModificationConfirm == nil)
				if v.bodySeNBModificationConfirm != nil {
					X2apInternalCompareX2APSeNBModificationConfirm(v.bodySeNBModificationConfirm, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(24):
			{
				f := s.Begin()
				s.Bool(v.bodySeNBReleaseConfirm == nil)
				if v.bodySeNBReleaseConfirm != nil {
					X2apInternalCompareX2APSeNBReleaseConfirm(v.bodySeNBReleaseConfirm, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(26):
			{
				f := s.Begin()
				s.Bool(v.bodyRetrieveUEContextResponse == nil)
				if v.bodyRetrieveUEContextResponse != nil {
					X2apInternalCompareX2APRetrieveUEContextResponse(v.bodyRetrieveUEContextResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(27):
			{
				f := s.Begin()
				s.Bool(v.bodySgNBAdditionRequestAcknowledge == nil)
				if v.bodySgNBAdditionRequestAcknowledge != nil {
					X2apInternalCompareX2APSgNBAdditionRequestAcknowledge(v.bodySgNBAdditionRequestAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(29):
			{
				f := s.Begin()
				s.Bool(v.bodySgNBModificationRequestAcknowledge == nil)
				if v.bodySgNBModificationRequestAcknowledge != nil {
					X2apInternalCompareX2APSgNBModificationRequestAcknowledge(v.bodySgNBModificationRequestAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(30):
			{
				f := s.Begin()
				s.Bool(v.bodySgNBModificationConfirm == nil)
				if v.bodySgNBModificationConfirm != nil {
					X2apInternalCompareX2APSgNBModificationConfirm(v.bodySgNBModificationConfirm, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(31):
			{
				f := s.Begin()
				s.Bool(v.bodySgNBReleaseRequestAcknowledge == nil)
				if v.bodySgNBReleaseRequestAcknowledge != nil {
					X2apInternalCompareX2APSgNBReleaseRequestAcknowledge(v.bodySgNBReleaseRequestAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(32):
			{
				f := s.Begin()
				s.Bool(v.bodySgNBReleaseConfirm == nil)
				if v.bodySgNBReleaseConfirm != nil {
					X2apInternalCompareX2APSgNBReleaseConfirm(v.bodySgNBReleaseConfirm, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(34):
			{
				f := s.Begin()
				s.Bool(v.bodySgNBChangeConfirm == nil)
				if v.bodySgNBChangeConfirm != nil {
					X2apInternalCompareX2APSgNBChangeConfirm(v.bodySgNBChangeConfirm, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(36):
			{
				f := s.Begin()
				s.Bool(v.bodyENDCX2SetupResponse == nil)
				if v.bodyENDCX2SetupResponse != nil {
					X2apInternalCompareX2APENDCX2SetupResponse(v.bodyENDCX2SetupResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(37):
			{
				f := s.Begin()
				s.Bool(v.bodyENDCConfigurationUpdateAcknowledge == nil)
				if v.bodyENDCConfigurationUpdateAcknowledge != nil {
					X2apInternalCompareX2APENDCConfigurationUpdateAcknowledge(v.bodyENDCConfigurationUpdateAcknowledge, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(39):
			{
				f := s.Begin()
				s.Bool(v.bodyENDCCellActivationResponse == nil)
				if v.bodyENDCCellActivationResponse != nil {
					X2apInternalCompareX2APENDCCellActivationResponse(v.bodyENDCCellActivationResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(40):
			{
				f := s.Begin()
				s.Bool(v.bodyENDCPartialResetConfirm == nil)
				if v.bodyENDCPartialResetConfirm != nil {
					X2apInternalCompareX2APENDCPartialResetConfirm(v.bodyENDCPartialResetConfirm, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(41):
			{
				f := s.Begin()
				s.Bool(v.bodyEUTRANRCellResourceCoordinationResponse == nil)
				if v.bodyEUTRANRCellResourceCoordinationResponse != nil {
					X2apInternalCompareX2APEUTRANRCellResourceCoordinationResponse(v.bodyEUTRANRCellResourceCoordinationResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(43):
			{
				f := s.Begin()
				s.Bool(v.bodyENDCX2RemovalResponse == nil)
				if v.bodyENDCX2RemovalResponse != nil {
					X2apInternalCompareX2APENDCX2RemovalResponse(v.bodyENDCX2RemovalResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(54):
			{
				f := s.Begin()
				s.Bool(v.bodyENDCResourceStatusResponse == nil)
				if v.bodyENDCResourceStatusResponse != nil {
					X2apInternalCompareX2APENDCResourceStatusResponse(v.bodyENDCResourceStatusResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(56):
			{
				f := s.Begin()
				s.Bool(v.bodyUERadioCapabilityIDMappingResponse == nil)
				if v.bodyUERadioCapabilityIDMappingResponse != nil {
					X2apInternalCompareX2APUERadioCapabilityIDMappingResponse(v.bodyUERadioCapabilityIDMappingResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
}
func X2apInternalSuccessfulValueCompareSemantics(v SuccessfulValue, s aper.SemanticComparison) aper.SemanticComparison {
	X2apInternalCompareX2APSuccessfulValue(&v, &s)
	return s
}
func X2apInternalCaptureX2APUERadioCapabilityIDMappingResponse(v *UERadioCapabilityIDMappingResponse, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s11.X2apInternalUERadioCapabilityIDMappingResponseIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APUERadioCapabilityIDMappingResponse(v *UERadioCapabilityIDMappingResponse, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s11.X2apInternalUERadioCapabilityIDMappingResponseIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APX2RemovalResponse(v *X2RemovalResponse, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s08.X2apInternalX2RemovalResponseIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APX2RemovalResponse(v *X2RemovalResponse, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s08.X2apInternalX2RemovalResponseIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APX2SetupResponse(v *X2SetupResponse, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s17.X2apInternalX2SetupResponseIEValuecaptureX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APX2SetupResponse(v *X2SetupResponse, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s17.X2apInternalX2SetupResponseIEValuecompareX2APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}

// SuccessfulOutcomeCodec binds the complete source value type.
func SuccessfulOutcomeCodec() SuccessfulOutcomeValueCodec {
	return SuccessfulOutcomeValueCodec{path: "SuccessfulOutcome", decode: func(data []byte, options aper.DecodeState) (SuccessfulOutcome, error) {
		var value SuccessfulOutcome
		if err := X2apInternalSuccessfulOutcomeUnmarshalAPERWithOptions(&value, data, options); err != nil {
			return SuccessfulOutcome{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SuccessfulOutcome, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return X2apInternalSuccessfulOutcomeMarshalAPERBudget((&value), budget, fresh)
	}, capture: func(v SuccessfulOutcome, options aper.DecodeState) (SuccessfulOutcome, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		X2apInternalCaptureX2APSuccessfulOutcome(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root

	}, compare: func(v SuccessfulOutcome, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		X2apInternalCompareX2APSuccessfulOutcome(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: s00.X2apInternalConstructT12codecContextF6source("source-value:SuccessfulOutcome"),
	}
}

// HandoverRequestAcknowledge represents the ASN.1 type HandoverRequestAcknowledge (SEQUENCE).
type HandoverRequestAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s14.HandoverRequestAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                      `asn1:"-" json:"-"`
	extCount         int64                                     `asn1:"-" json:"-"`
	extPresent       []bool                                    `asn1:"-" json:"-"`
	extData          [][]byte                                  `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ResetResponse represents the ASN.1 type ResetResponse (SEQUENCE).
type ResetResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s07.ResetResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                         `asn1:"-" json:"-"`
	extCount         int64                        `asn1:"-" json:"-"`
	extPresent       []bool                       `asn1:"-" json:"-"`
	extData          [][]byte                     `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding            `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding       `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// X2SetupResponse represents the ASN.1 type X2SetupResponse (SEQUENCE).
type X2SetupResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s17.X2SetupResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                           `asn1:"-" json:"-"`
	extCount         int64                          `asn1:"-" json:"-"`
	extPresent       []bool                         `asn1:"-" json:"-"`
	extData          [][]byte                       `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding              `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding         `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ENBConfigurationUpdateAcknowledge represents the ASN.1 type ENBConfigurationUpdateAcknowledge (SEQUENCE).
type ENBConfigurationUpdateAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s06.ENBConfigurationUpdateAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                             `asn1:"-" json:"-"`
	extCount         int64                                            `asn1:"-" json:"-"`
	extPresent       []bool                                           `asn1:"-" json:"-"`
	extData          [][]byte                                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ResourceStatusResponse represents the ASN.1 type ResourceStatusResponse (SEQUENCE).
type ResourceStatusResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s16.ResourceStatusResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                  `asn1:"-" json:"-"`
	extCount         int64                                 `asn1:"-" json:"-"`
	extPresent       []bool                                `asn1:"-" json:"-"`
	extData          [][]byte                              `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MobilityChangeAcknowledge represents the ASN.1 type MobilityChangeAcknowledge (SEQUENCE).
type MobilityChangeAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s07.MobilityChangeAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                     `asn1:"-" json:"-"`
	extCount         int64                                    `asn1:"-" json:"-"`
	extPresent       []bool                                   `asn1:"-" json:"-"`
	extData          [][]byte                                 `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// CellActivationResponse represents the ASN.1 type CellActivationResponse (SEQUENCE).
type CellActivationResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s13.CellActivationResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                  `asn1:"-" json:"-"`
	extCount         int64                                 `asn1:"-" json:"-"`
	extPresent       []bool                                `asn1:"-" json:"-"`
	extData          [][]byte                              `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// SeNBAdditionRequestAcknowledge represents the ASN.1 type SeNBAdditionRequestAcknowledge (SEQUENCE).
type SeNBAdditionRequestAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s15.SeNBAdditionRequestAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                          `asn1:"-" json:"-"`
	extCount         int64                                         `asn1:"-" json:"-"`
	extPresent       []bool                                        `asn1:"-" json:"-"`
	extData          [][]byte                                      `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// SeNBModificationRequestAcknowledge represents the ASN.1 type SeNBModificationRequestAcknowledge (SEQUENCE).
type SeNBModificationRequestAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s15.SeNBModificationRequestAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                              `asn1:"-" json:"-"`
	extCount         int64                                             `asn1:"-" json:"-"`
	extPresent       []bool                                            `asn1:"-" json:"-"`
	extData          [][]byte                                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// SeNBModificationConfirm represents the ASN.1 type SeNBModificationConfirm (SEQUENCE).
type SeNBModificationConfirm struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s12.SeNBModificationConfirmIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                   `asn1:"-" json:"-"`
	extCount         int64                                  `asn1:"-" json:"-"`
	extPresent       []bool                                 `asn1:"-" json:"-"`
	extData          [][]byte                               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// SeNBReleaseConfirm represents the ASN.1 type SeNBReleaseConfirm (SEQUENCE).
type SeNBReleaseConfirm struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s15.SeNBReleaseConfirmIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                              `asn1:"-" json:"-"`
	extCount         int64                             `asn1:"-" json:"-"`
	extPresent       []bool                            `asn1:"-" json:"-"`
	extData          [][]byte                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// X2RemovalResponse represents the ASN.1 type X2RemovalResponse (SEQUENCE).
type X2RemovalResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s07.X2RemovalResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                             `asn1:"-" json:"-"`
	extCount         int64                            `asn1:"-" json:"-"`
	extPresent       []bool                           `asn1:"-" json:"-"`
	extData          [][]byte                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// RetrieveUEContextResponse represents the ASN.1 type RetrieveUEContextResponse (SEQUENCE).
type RetrieveUEContextResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s17.RetrieveUEContextResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                     `asn1:"-" json:"-"`
	extCount         int64                                    `asn1:"-" json:"-"`
	extPresent       []bool                                   `asn1:"-" json:"-"`
	extData          [][]byte                                 `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// SgNBAdditionRequestAcknowledge represents the ASN.1 type SgNBAdditionRequestAcknowledge (SEQUENCE).
type SgNBAdditionRequestAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s15.SgNBAdditionRequestAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                          `asn1:"-" json:"-"`
	extCount         int64                                         `asn1:"-" json:"-"`
	extPresent       []bool                                        `asn1:"-" json:"-"`
	extData          [][]byte                                      `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// SgNBModificationRequestAcknowledge represents the ASN.1 type SgNBModificationRequestAcknowledge (SEQUENCE).
type SgNBModificationRequestAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s17.SgNBModificationRequestAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                              `asn1:"-" json:"-"`
	extCount         int64                                             `asn1:"-" json:"-"`
	extPresent       []bool                                            `asn1:"-" json:"-"`
	extData          [][]byte                                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// SgNBModificationConfirm represents the ASN.1 type SgNBModificationConfirm (SEQUENCE).
type SgNBModificationConfirm struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s15.SgNBModificationConfirmIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                   `asn1:"-" json:"-"`
	extCount         int64                                  `asn1:"-" json:"-"`
	extPresent       []bool                                 `asn1:"-" json:"-"`
	extData          [][]byte                               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// SgNBReleaseRequestAcknowledge represents the ASN.1 type SgNBReleaseRequestAcknowledge (SEQUENCE).
type SgNBReleaseRequestAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s17.SgNBReleaseRequestAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                         `asn1:"-" json:"-"`
	extCount         int64                                        `asn1:"-" json:"-"`
	extPresent       []bool                                       `asn1:"-" json:"-"`
	extData          [][]byte                                     `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// SgNBReleaseConfirm represents the ASN.1 type SgNBReleaseConfirm (SEQUENCE).
type SgNBReleaseConfirm struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s15.SgNBReleaseConfirmIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                              `asn1:"-" json:"-"`
	extCount         int64                             `asn1:"-" json:"-"`
	extPresent       []bool                            `asn1:"-" json:"-"`
	extData          [][]byte                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// SgNBChangeConfirm represents the ASN.1 type SgNBChangeConfirm (SEQUENCE).
type SgNBChangeConfirm struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s15.SgNBChangeConfirmIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                             `asn1:"-" json:"-"`
	extCount         int64                            `asn1:"-" json:"-"`
	extPresent       []bool                           `asn1:"-" json:"-"`
	extData          [][]byte                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ENDCX2SetupResponse represents the ASN.1 type ENDCX2SetupResponse (SEQUENCE).
type ENDCX2SetupResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s18.ENDCX2SetupResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                               `asn1:"-" json:"-"`
	extCount         int64                              `asn1:"-" json:"-"`
	extPresent       []bool                             `asn1:"-" json:"-"`
	extData          [][]byte                           `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ENDCConfigurationUpdateAcknowledge represents the ASN.1 type ENDCConfigurationUpdateAcknowledge (SEQUENCE).
type ENDCConfigurationUpdateAcknowledge struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s18.ENDCConfigurationUpdateAcknowledgeIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                              `asn1:"-" json:"-"`
	extCount         int64                                             `asn1:"-" json:"-"`
	extPresent       []bool                                            `asn1:"-" json:"-"`
	extData          [][]byte                                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ENDCCellActivationResponse represents the ASN.1 type ENDCCellActivationResponse (SEQUENCE).
type ENDCCellActivationResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s13.ENDCCellActivationResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                      `asn1:"-" json:"-"`
	extCount         int64                                     `asn1:"-" json:"-"`
	extPresent       []bool                                    `asn1:"-" json:"-"`
	extData          [][]byte                                  `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ENDCResourceStatusResponse represents the ASN.1 type ENDCResourceStatusResponse (SEQUENCE).
type ENDCResourceStatusResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s06.ENDCResourceStatusResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                      `asn1:"-" json:"-"`
	extCount         int64                                     `asn1:"-" json:"-"`
	extPresent       []bool                                    `asn1:"-" json:"-"`
	extData          [][]byte                                  `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ENDCPartialResetConfirm represents the ASN.1 type ENDCPartialResetConfirm (SEQUENCE).
type ENDCPartialResetConfirm struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s18.ENDCPartialResetConfirmIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                   `asn1:"-" json:"-"`
	extCount         int64                                  `asn1:"-" json:"-"`
	extPresent       []bool                                 `asn1:"-" json:"-"`
	extData          [][]byte                               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// EUTRANRCellResourceCoordinationResponse represents the ASN.1 type EUTRANRCellResourceCoordinationResponse (SEQUENCE).
type EUTRANRCellResourceCoordinationResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s16.EUTRANRCellResourceCoordinationResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                                   `asn1:"-" json:"-"`
	extCount         int64                                                  `asn1:"-" json:"-"`
	extPresent       []bool                                                 `asn1:"-" json:"-"`
	extData          [][]byte                                               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                                 `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ENDCX2RemovalResponse represents the ASN.1 type ENDCX2RemovalResponse (SEQUENCE).
type ENDCX2RemovalResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s07.ENDCX2RemovalResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                 `asn1:"-" json:"-"`
	extCount         int64                                `asn1:"-" json:"-"`
	extPresent       []bool                               `asn1:"-" json:"-"`
	extData          [][]byte                             `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding               `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UERadioCapabilityIDMappingResponse represents the ASN.1 type UERadioCapabilityIDMappingResponse (SEQUENCE).
type UERadioCapabilityIDMappingResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s11.UERadioCapabilityIDMappingResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                              `asn1:"-" json:"-"`
	extCount         int64                                             `asn1:"-" json:"-"`
	extPresent       []bool                                            `asn1:"-" json:"-"`
	extData          [][]byte                                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes HandoverRequestAcknowledge to APER format.
func X2apInternalHandoverRequestAcknowledgeMarshalAPERLegacy(v *HandoverRequestAcknowledge) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalHandoverRequestAcknowledgeMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalHandoverRequestAcknowledgeMarshalAPERTo(v *HandoverRequestAcknowledge, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s14.X2apInternalHandoverRequestAcknowledgeIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes HandoverRequestAcknowledge from APER format.
func X2apInternalHandoverRequestAcknowledgeUnmarshalAPERLegacy(v *HandoverRequestAcknowledge, data []byte) error {
	return X2apInternalHandoverRequestAcknowledgeUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes HandoverRequestAcknowledge with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalHandoverRequestAcknowledgeUnmarshalAPERWithOptions(v *HandoverRequestAcknowledge, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequestAcknowledge")
	}
	bb.EnterComponent("HandoverRequestAcknowledge")
	if err := X2apInternalHandoverRequestAcknowledgeUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequestAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "HandoverRequestAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequestAcknowledge")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalHandoverRequestAcknowledgeUnmarshalAPERFrom(v *HandoverRequestAcknowledge, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverRequestAcknowledge{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s14.HandoverRequestAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s14.HandoverRequestAcknowledgeIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s14.X2apInternalHandoverRequestAcknowledgeIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes ResetResponse to APER format.
func X2apInternalResetResponseMarshalAPERLegacy(v *ResetResponse) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalResetResponseMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalResetResponseMarshalAPERTo(v *ResetResponse, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s07.X2apInternalResetResponseIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ResetResponse from APER format.
func X2apInternalResetResponseUnmarshalAPERLegacy(v *ResetResponse, data []byte) error {
	return X2apInternalResetResponseUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResetResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalResetResponseUnmarshalAPERWithOptions(v *ResetResponse, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResetResponse")
	}
	bb.EnterComponent("ResetResponse")
	if err := X2apInternalResetResponseUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "ResetResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResetResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResetResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalResetResponseUnmarshalAPERFrom(v *ResetResponse, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResetResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s07.ResetResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s07.ResetResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s07.X2apInternalResetResponseIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes X2SetupResponse to APER format.
func X2apInternalX2SetupResponseMarshalAPERLegacy(v *X2SetupResponse) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalX2SetupResponseMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalX2SetupResponseMarshalAPERTo(v *X2SetupResponse, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s17.X2apInternalX2SetupResponseIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes X2SetupResponse from APER format.
func X2apInternalX2SetupResponseUnmarshalAPERLegacy(v *X2SetupResponse, data []byte) error {
	return X2apInternalX2SetupResponseUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes X2SetupResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalX2SetupResponseUnmarshalAPERWithOptions(v *X2SetupResponse, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "X2SetupResponse")
	}
	bb.EnterComponent("X2SetupResponse")
	if err := X2apInternalX2SetupResponseUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "X2SetupResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "X2SetupResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "X2SetupResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalX2SetupResponseUnmarshalAPERFrom(v *X2SetupResponse, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = X2SetupResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s17.X2SetupResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s17.X2SetupResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s17.X2apInternalX2SetupResponseIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes ENBConfigurationUpdateAcknowledge to APER format.
func X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERLegacy(v *ENBConfigurationUpdateAcknowledge) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERTo(v *ENBConfigurationUpdateAcknowledge, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s06.X2apInternalENBConfigurationUpdateAcknowledgeIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ENBConfigurationUpdateAcknowledge from APER format.
func X2apInternalENBConfigurationUpdateAcknowledgeUnmarshalAPERLegacy(v *ENBConfigurationUpdateAcknowledge, data []byte) error {
	return X2apInternalENBConfigurationUpdateAcknowledgeUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENBConfigurationUpdateAcknowledge with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalENBConfigurationUpdateAcknowledgeUnmarshalAPERWithOptions(v *ENBConfigurationUpdateAcknowledge, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledge")
	}
	bb.EnterComponent("ENBConfigurationUpdateAcknowledge")
	if err := X2apInternalENBConfigurationUpdateAcknowledgeUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENBConfigurationUpdateAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBConfigurationUpdateAcknowledge")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalENBConfigurationUpdateAcknowledgeUnmarshalAPERFrom(v *ENBConfigurationUpdateAcknowledge, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENBConfigurationUpdateAcknowledge{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s06.ENBConfigurationUpdateAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s06.ENBConfigurationUpdateAcknowledgeIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s06.X2apInternalENBConfigurationUpdateAcknowledgeIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes ResourceStatusResponse to APER format.
func X2apInternalResourceStatusResponseMarshalAPERLegacy(v *ResourceStatusResponse) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalResourceStatusResponseMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalResourceStatusResponseMarshalAPERTo(v *ResourceStatusResponse, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s16.X2apInternalResourceStatusResponseIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ResourceStatusResponse from APER format.
func X2apInternalResourceStatusResponseUnmarshalAPERLegacy(v *ResourceStatusResponse, data []byte) error {
	return X2apInternalResourceStatusResponseUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResourceStatusResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalResourceStatusResponseUnmarshalAPERWithOptions(v *ResourceStatusResponse, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResourceStatusResponse")
	}
	bb.EnterComponent("ResourceStatusResponse")
	if err := X2apInternalResourceStatusResponseUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "ResourceStatusResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResourceStatusResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResourceStatusResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalResourceStatusResponseUnmarshalAPERFrom(v *ResourceStatusResponse, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResourceStatusResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s16.ResourceStatusResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s16.ResourceStatusResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s16.X2apInternalResourceStatusResponseIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes MobilityChangeAcknowledge to APER format.
func X2apInternalMobilityChangeAcknowledgeMarshalAPERLegacy(v *MobilityChangeAcknowledge) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalMobilityChangeAcknowledgeMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalMobilityChangeAcknowledgeMarshalAPERTo(v *MobilityChangeAcknowledge, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s07.X2apInternalMobilityChangeAcknowledgeIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes MobilityChangeAcknowledge from APER format.
func X2apInternalMobilityChangeAcknowledgeUnmarshalAPERLegacy(v *MobilityChangeAcknowledge, data []byte) error {
	return X2apInternalMobilityChangeAcknowledgeUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MobilityChangeAcknowledge with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalMobilityChangeAcknowledgeUnmarshalAPERWithOptions(v *MobilityChangeAcknowledge, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MobilityChangeAcknowledge")
	}
	bb.EnterComponent("MobilityChangeAcknowledge")
	if err := X2apInternalMobilityChangeAcknowledgeUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "MobilityChangeAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "MobilityChangeAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "MobilityChangeAcknowledge")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalMobilityChangeAcknowledgeUnmarshalAPERFrom(v *MobilityChangeAcknowledge, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MobilityChangeAcknowledge{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s07.MobilityChangeAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s07.MobilityChangeAcknowledgeIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s07.X2apInternalMobilityChangeAcknowledgeIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes CellActivationResponse to APER format.
func X2apInternalCellActivationResponseMarshalAPERLegacy(v *CellActivationResponse) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalCellActivationResponseMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalCellActivationResponseMarshalAPERTo(v *CellActivationResponse, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s13.X2apInternalCellActivationResponseIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes CellActivationResponse from APER format.
func X2apInternalCellActivationResponseUnmarshalAPERLegacy(v *CellActivationResponse, data []byte) error {
	return X2apInternalCellActivationResponseUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CellActivationResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalCellActivationResponseUnmarshalAPERWithOptions(v *CellActivationResponse, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "CellActivationResponse")
	}
	bb.EnterComponent("CellActivationResponse")
	if err := X2apInternalCellActivationResponseUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "CellActivationResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "CellActivationResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "CellActivationResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalCellActivationResponseUnmarshalAPERFrom(v *CellActivationResponse, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = CellActivationResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s13.CellActivationResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s13.CellActivationResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s13.X2apInternalCellActivationResponseIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes SeNBAdditionRequestAcknowledge to APER format.
func X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERLegacy(v *SeNBAdditionRequestAcknowledge) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERTo(v *SeNBAdditionRequestAcknowledge, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s15.X2apInternalSeNBAdditionRequestAcknowledgeIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes SeNBAdditionRequestAcknowledge from APER format.
func X2apInternalSeNBAdditionRequestAcknowledgeUnmarshalAPERLegacy(v *SeNBAdditionRequestAcknowledge, data []byte) error {
	return X2apInternalSeNBAdditionRequestAcknowledgeUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SeNBAdditionRequestAcknowledge with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalSeNBAdditionRequestAcknowledgeUnmarshalAPERWithOptions(v *SeNBAdditionRequestAcknowledge, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SeNBAdditionRequestAcknowledge")
	}
	bb.EnterComponent("SeNBAdditionRequestAcknowledge")
	if err := X2apInternalSeNBAdditionRequestAcknowledgeUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "SeNBAdditionRequestAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "SeNBAdditionRequestAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "SeNBAdditionRequestAcknowledge")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalSeNBAdditionRequestAcknowledgeUnmarshalAPERFrom(v *SeNBAdditionRequestAcknowledge, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SeNBAdditionRequestAcknowledge{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s15.SeNBAdditionRequestAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s15.SeNBAdditionRequestAcknowledgeIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s15.X2apInternalSeNBAdditionRequestAcknowledgeIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes SeNBModificationRequestAcknowledge to APER format.
func X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERLegacy(v *SeNBModificationRequestAcknowledge) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERTo(v *SeNBModificationRequestAcknowledge, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s15.X2apInternalSeNBModificationRequestAcknowledgeIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes SeNBModificationRequestAcknowledge from APER format.
func X2apInternalSeNBModificationRequestAcknowledgeUnmarshalAPERLegacy(v *SeNBModificationRequestAcknowledge, data []byte) error {
	return X2apInternalSeNBModificationRequestAcknowledgeUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SeNBModificationRequestAcknowledge with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalSeNBModificationRequestAcknowledgeUnmarshalAPERWithOptions(v *SeNBModificationRequestAcknowledge, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SeNBModificationRequestAcknowledge")
	}
	bb.EnterComponent("SeNBModificationRequestAcknowledge")
	if err := X2apInternalSeNBModificationRequestAcknowledgeUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "SeNBModificationRequestAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "SeNBModificationRequestAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "SeNBModificationRequestAcknowledge")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalSeNBModificationRequestAcknowledgeUnmarshalAPERFrom(v *SeNBModificationRequestAcknowledge, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SeNBModificationRequestAcknowledge{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s15.SeNBModificationRequestAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s15.SeNBModificationRequestAcknowledgeIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s15.X2apInternalSeNBModificationRequestAcknowledgeIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes SeNBModificationConfirm to APER format.
func X2apInternalSeNBModificationConfirmMarshalAPERLegacy(v *SeNBModificationConfirm) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalSeNBModificationConfirmMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalSeNBModificationConfirmMarshalAPERTo(v *SeNBModificationConfirm, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s12.X2apInternalSeNBModificationConfirmIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes SeNBModificationConfirm from APER format.
func X2apInternalSeNBModificationConfirmUnmarshalAPERLegacy(v *SeNBModificationConfirm, data []byte) error {
	return X2apInternalSeNBModificationConfirmUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SeNBModificationConfirm with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalSeNBModificationConfirmUnmarshalAPERWithOptions(v *SeNBModificationConfirm, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SeNBModificationConfirm")
	}
	bb.EnterComponent("SeNBModificationConfirm")
	if err := X2apInternalSeNBModificationConfirmUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "SeNBModificationConfirm")
	}
	padding, err := aper.CaptureFinalBits(bb, "SeNBModificationConfirm")
	if err != nil {
		return runtime.WrapDecodePath(err, "SeNBModificationConfirm")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalSeNBModificationConfirmUnmarshalAPERFrom(v *SeNBModificationConfirm, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SeNBModificationConfirm{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s12.SeNBModificationConfirmIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s12.SeNBModificationConfirmIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s12.X2apInternalSeNBModificationConfirmIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes SeNBReleaseConfirm to APER format.
func X2apInternalSeNBReleaseConfirmMarshalAPERLegacy(v *SeNBReleaseConfirm) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalSeNBReleaseConfirmMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalSeNBReleaseConfirmMarshalAPERTo(v *SeNBReleaseConfirm, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s15.X2apInternalSeNBReleaseConfirmIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes SeNBReleaseConfirm from APER format.
func X2apInternalSeNBReleaseConfirmUnmarshalAPERLegacy(v *SeNBReleaseConfirm, data []byte) error {
	return X2apInternalSeNBReleaseConfirmUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SeNBReleaseConfirm with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalSeNBReleaseConfirmUnmarshalAPERWithOptions(v *SeNBReleaseConfirm, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SeNBReleaseConfirm")
	}
	bb.EnterComponent("SeNBReleaseConfirm")
	if err := X2apInternalSeNBReleaseConfirmUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "SeNBReleaseConfirm")
	}
	padding, err := aper.CaptureFinalBits(bb, "SeNBReleaseConfirm")
	if err != nil {
		return runtime.WrapDecodePath(err, "SeNBReleaseConfirm")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalSeNBReleaseConfirmUnmarshalAPERFrom(v *SeNBReleaseConfirm, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SeNBReleaseConfirm{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s15.SeNBReleaseConfirmIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s15.SeNBReleaseConfirmIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s15.X2apInternalSeNBReleaseConfirmIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes X2RemovalResponse to APER format.
func X2apInternalX2RemovalResponseMarshalAPERLegacy(v *X2RemovalResponse) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalX2RemovalResponseMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalX2RemovalResponseMarshalAPERTo(v *X2RemovalResponse, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s07.X2apInternalX2RemovalResponseIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes X2RemovalResponse from APER format.
func X2apInternalX2RemovalResponseUnmarshalAPERLegacy(v *X2RemovalResponse, data []byte) error {
	return X2apInternalX2RemovalResponseUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes X2RemovalResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalX2RemovalResponseUnmarshalAPERWithOptions(v *X2RemovalResponse, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "X2RemovalResponse")
	}
	bb.EnterComponent("X2RemovalResponse")
	if err := X2apInternalX2RemovalResponseUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "X2RemovalResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "X2RemovalResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "X2RemovalResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalX2RemovalResponseUnmarshalAPERFrom(v *X2RemovalResponse, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = X2RemovalResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s07.X2RemovalResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s07.X2RemovalResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s07.X2apInternalX2RemovalResponseIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes RetrieveUEContextResponse to APER format.
func X2apInternalRetrieveUEContextResponseMarshalAPERLegacy(v *RetrieveUEContextResponse) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalRetrieveUEContextResponseMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalRetrieveUEContextResponseMarshalAPERTo(v *RetrieveUEContextResponse, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s17.X2apInternalRetrieveUEContextResponseIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes RetrieveUEContextResponse from APER format.
func X2apInternalRetrieveUEContextResponseUnmarshalAPERLegacy(v *RetrieveUEContextResponse, data []byte) error {
	return X2apInternalRetrieveUEContextResponseUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RetrieveUEContextResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalRetrieveUEContextResponseUnmarshalAPERWithOptions(v *RetrieveUEContextResponse, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RetrieveUEContextResponse")
	}
	bb.EnterComponent("RetrieveUEContextResponse")
	if err := X2apInternalRetrieveUEContextResponseUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "RetrieveUEContextResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "RetrieveUEContextResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "RetrieveUEContextResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalRetrieveUEContextResponseUnmarshalAPERFrom(v *RetrieveUEContextResponse, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RetrieveUEContextResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s17.RetrieveUEContextResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s17.RetrieveUEContextResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s17.X2apInternalRetrieveUEContextResponseIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes SgNBAdditionRequestAcknowledge to APER format.
func X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERLegacy(v *SgNBAdditionRequestAcknowledge) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERTo(v *SgNBAdditionRequestAcknowledge, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s15.X2apInternalSgNBAdditionRequestAcknowledgeIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes SgNBAdditionRequestAcknowledge from APER format.
func X2apInternalSgNBAdditionRequestAcknowledgeUnmarshalAPERLegacy(v *SgNBAdditionRequestAcknowledge, data []byte) error {
	return X2apInternalSgNBAdditionRequestAcknowledgeUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SgNBAdditionRequestAcknowledge with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalSgNBAdditionRequestAcknowledgeUnmarshalAPERWithOptions(v *SgNBAdditionRequestAcknowledge, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SgNBAdditionRequestAcknowledge")
	}
	bb.EnterComponent("SgNBAdditionRequestAcknowledge")
	if err := X2apInternalSgNBAdditionRequestAcknowledgeUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "SgNBAdditionRequestAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "SgNBAdditionRequestAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "SgNBAdditionRequestAcknowledge")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalSgNBAdditionRequestAcknowledgeUnmarshalAPERFrom(v *SgNBAdditionRequestAcknowledge, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SgNBAdditionRequestAcknowledge{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s15.SgNBAdditionRequestAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s15.SgNBAdditionRequestAcknowledgeIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s15.X2apInternalSgNBAdditionRequestAcknowledgeIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes SgNBModificationRequestAcknowledge to APER format.
func X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERLegacy(v *SgNBModificationRequestAcknowledge) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERTo(v *SgNBModificationRequestAcknowledge, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s17.X2apInternalSgNBModificationRequestAcknowledgeIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes SgNBModificationRequestAcknowledge from APER format.
func X2apInternalSgNBModificationRequestAcknowledgeUnmarshalAPERLegacy(v *SgNBModificationRequestAcknowledge, data []byte) error {
	return X2apInternalSgNBModificationRequestAcknowledgeUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SgNBModificationRequestAcknowledge with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalSgNBModificationRequestAcknowledgeUnmarshalAPERWithOptions(v *SgNBModificationRequestAcknowledge, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SgNBModificationRequestAcknowledge")
	}
	bb.EnterComponent("SgNBModificationRequestAcknowledge")
	if err := X2apInternalSgNBModificationRequestAcknowledgeUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "SgNBModificationRequestAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "SgNBModificationRequestAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "SgNBModificationRequestAcknowledge")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalSgNBModificationRequestAcknowledgeUnmarshalAPERFrom(v *SgNBModificationRequestAcknowledge, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SgNBModificationRequestAcknowledge{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s17.SgNBModificationRequestAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s17.SgNBModificationRequestAcknowledgeIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s17.X2apInternalSgNBModificationRequestAcknowledgeIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes SgNBModificationConfirm to APER format.
func X2apInternalSgNBModificationConfirmMarshalAPERLegacy(v *SgNBModificationConfirm) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalSgNBModificationConfirmMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalSgNBModificationConfirmMarshalAPERTo(v *SgNBModificationConfirm, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s15.X2apInternalSgNBModificationConfirmIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes SgNBModificationConfirm from APER format.
func X2apInternalSgNBModificationConfirmUnmarshalAPERLegacy(v *SgNBModificationConfirm, data []byte) error {
	return X2apInternalSgNBModificationConfirmUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SgNBModificationConfirm with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalSgNBModificationConfirmUnmarshalAPERWithOptions(v *SgNBModificationConfirm, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SgNBModificationConfirm")
	}
	bb.EnterComponent("SgNBModificationConfirm")
	if err := X2apInternalSgNBModificationConfirmUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "SgNBModificationConfirm")
	}
	padding, err := aper.CaptureFinalBits(bb, "SgNBModificationConfirm")
	if err != nil {
		return runtime.WrapDecodePath(err, "SgNBModificationConfirm")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalSgNBModificationConfirmUnmarshalAPERFrom(v *SgNBModificationConfirm, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SgNBModificationConfirm{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s15.SgNBModificationConfirmIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s15.SgNBModificationConfirmIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s15.X2apInternalSgNBModificationConfirmIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes SgNBReleaseRequestAcknowledge to APER format.
func X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERLegacy(v *SgNBReleaseRequestAcknowledge) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERTo(v *SgNBReleaseRequestAcknowledge, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s17.X2apInternalSgNBReleaseRequestAcknowledgeIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes SgNBReleaseRequestAcknowledge from APER format.
func X2apInternalSgNBReleaseRequestAcknowledgeUnmarshalAPERLegacy(v *SgNBReleaseRequestAcknowledge, data []byte) error {
	return X2apInternalSgNBReleaseRequestAcknowledgeUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SgNBReleaseRequestAcknowledge with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalSgNBReleaseRequestAcknowledgeUnmarshalAPERWithOptions(v *SgNBReleaseRequestAcknowledge, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SgNBReleaseRequestAcknowledge")
	}
	bb.EnterComponent("SgNBReleaseRequestAcknowledge")
	if err := X2apInternalSgNBReleaseRequestAcknowledgeUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "SgNBReleaseRequestAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "SgNBReleaseRequestAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "SgNBReleaseRequestAcknowledge")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalSgNBReleaseRequestAcknowledgeUnmarshalAPERFrom(v *SgNBReleaseRequestAcknowledge, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SgNBReleaseRequestAcknowledge{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s17.SgNBReleaseRequestAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s17.SgNBReleaseRequestAcknowledgeIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s17.X2apInternalSgNBReleaseRequestAcknowledgeIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes SgNBReleaseConfirm to APER format.
func X2apInternalSgNBReleaseConfirmMarshalAPERLegacy(v *SgNBReleaseConfirm) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalSgNBReleaseConfirmMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalSgNBReleaseConfirmMarshalAPERTo(v *SgNBReleaseConfirm, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s15.X2apInternalSgNBReleaseConfirmIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes SgNBReleaseConfirm from APER format.
func X2apInternalSgNBReleaseConfirmUnmarshalAPERLegacy(v *SgNBReleaseConfirm, data []byte) error {
	return X2apInternalSgNBReleaseConfirmUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SgNBReleaseConfirm with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalSgNBReleaseConfirmUnmarshalAPERWithOptions(v *SgNBReleaseConfirm, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SgNBReleaseConfirm")
	}
	bb.EnterComponent("SgNBReleaseConfirm")
	if err := X2apInternalSgNBReleaseConfirmUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "SgNBReleaseConfirm")
	}
	padding, err := aper.CaptureFinalBits(bb, "SgNBReleaseConfirm")
	if err != nil {
		return runtime.WrapDecodePath(err, "SgNBReleaseConfirm")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalSgNBReleaseConfirmUnmarshalAPERFrom(v *SgNBReleaseConfirm, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SgNBReleaseConfirm{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s15.SgNBReleaseConfirmIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s15.SgNBReleaseConfirmIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s15.X2apInternalSgNBReleaseConfirmIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes SgNBChangeConfirm to APER format.
func X2apInternalSgNBChangeConfirmMarshalAPERLegacy(v *SgNBChangeConfirm) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalSgNBChangeConfirmMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalSgNBChangeConfirmMarshalAPERTo(v *SgNBChangeConfirm, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s15.X2apInternalSgNBChangeConfirmIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes SgNBChangeConfirm from APER format.
func X2apInternalSgNBChangeConfirmUnmarshalAPERLegacy(v *SgNBChangeConfirm, data []byte) error {
	return X2apInternalSgNBChangeConfirmUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SgNBChangeConfirm with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalSgNBChangeConfirmUnmarshalAPERWithOptions(v *SgNBChangeConfirm, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SgNBChangeConfirm")
	}
	bb.EnterComponent("SgNBChangeConfirm")
	if err := X2apInternalSgNBChangeConfirmUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "SgNBChangeConfirm")
	}
	padding, err := aper.CaptureFinalBits(bb, "SgNBChangeConfirm")
	if err != nil {
		return runtime.WrapDecodePath(err, "SgNBChangeConfirm")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalSgNBChangeConfirmUnmarshalAPERFrom(v *SgNBChangeConfirm, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SgNBChangeConfirm{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s15.SgNBChangeConfirmIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s15.SgNBChangeConfirmIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s15.X2apInternalSgNBChangeConfirmIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes ENDCX2SetupResponse to APER format.
func X2apInternalENDCX2SetupResponseMarshalAPERLegacy(v *ENDCX2SetupResponse) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalENDCX2SetupResponseMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalENDCX2SetupResponseMarshalAPERTo(v *ENDCX2SetupResponse, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s18.X2apInternalENDCX2SetupResponseIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ENDCX2SetupResponse from APER format.
func X2apInternalENDCX2SetupResponseUnmarshalAPERLegacy(v *ENDCX2SetupResponse, data []byte) error {
	return X2apInternalENDCX2SetupResponseUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENDCX2SetupResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalENDCX2SetupResponseUnmarshalAPERWithOptions(v *ENDCX2SetupResponse, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENDCX2SetupResponse")
	}
	bb.EnterComponent("ENDCX2SetupResponse")
	if err := X2apInternalENDCX2SetupResponseUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "ENDCX2SetupResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENDCX2SetupResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENDCX2SetupResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalENDCX2SetupResponseUnmarshalAPERFrom(v *ENDCX2SetupResponse, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCX2SetupResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s18.ENDCX2SetupResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s18.ENDCX2SetupResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s18.X2apInternalENDCX2SetupResponseIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes ENDCConfigurationUpdateAcknowledge to APER format.
func X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERLegacy(v *ENDCConfigurationUpdateAcknowledge) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERTo(v *ENDCConfigurationUpdateAcknowledge, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s18.X2apInternalENDCConfigurationUpdateAcknowledgeIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ENDCConfigurationUpdateAcknowledge from APER format.
func X2apInternalENDCConfigurationUpdateAcknowledgeUnmarshalAPERLegacy(v *ENDCConfigurationUpdateAcknowledge, data []byte) error {
	return X2apInternalENDCConfigurationUpdateAcknowledgeUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENDCConfigurationUpdateAcknowledge with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalENDCConfigurationUpdateAcknowledgeUnmarshalAPERWithOptions(v *ENDCConfigurationUpdateAcknowledge, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENDCConfigurationUpdateAcknowledge")
	}
	bb.EnterComponent("ENDCConfigurationUpdateAcknowledge")
	if err := X2apInternalENDCConfigurationUpdateAcknowledgeUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "ENDCConfigurationUpdateAcknowledge")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENDCConfigurationUpdateAcknowledge")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENDCConfigurationUpdateAcknowledge")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalENDCConfigurationUpdateAcknowledgeUnmarshalAPERFrom(v *ENDCConfigurationUpdateAcknowledge, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCConfigurationUpdateAcknowledge{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s18.ENDCConfigurationUpdateAcknowledgeIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s18.ENDCConfigurationUpdateAcknowledgeIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s18.X2apInternalENDCConfigurationUpdateAcknowledgeIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes ENDCCellActivationResponse to APER format.
func X2apInternalENDCCellActivationResponseMarshalAPERLegacy(v *ENDCCellActivationResponse) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalENDCCellActivationResponseMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalENDCCellActivationResponseMarshalAPERTo(v *ENDCCellActivationResponse, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s13.X2apInternalENDCCellActivationResponseIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ENDCCellActivationResponse from APER format.
func X2apInternalENDCCellActivationResponseUnmarshalAPERLegacy(v *ENDCCellActivationResponse, data []byte) error {
	return X2apInternalENDCCellActivationResponseUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENDCCellActivationResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalENDCCellActivationResponseUnmarshalAPERWithOptions(v *ENDCCellActivationResponse, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENDCCellActivationResponse")
	}
	bb.EnterComponent("ENDCCellActivationResponse")
	if err := X2apInternalENDCCellActivationResponseUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "ENDCCellActivationResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENDCCellActivationResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENDCCellActivationResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalENDCCellActivationResponseUnmarshalAPERFrom(v *ENDCCellActivationResponse, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCCellActivationResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s13.ENDCCellActivationResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s13.ENDCCellActivationResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s13.X2apInternalENDCCellActivationResponseIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes ENDCResourceStatusResponse to APER format.
func X2apInternalENDCResourceStatusResponseMarshalAPERLegacy(v *ENDCResourceStatusResponse) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalENDCResourceStatusResponseMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalENDCResourceStatusResponseMarshalAPERTo(v *ENDCResourceStatusResponse, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s06.X2apInternalENDCResourceStatusResponseIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ENDCResourceStatusResponse from APER format.
func X2apInternalENDCResourceStatusResponseUnmarshalAPERLegacy(v *ENDCResourceStatusResponse, data []byte) error {
	return X2apInternalENDCResourceStatusResponseUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENDCResourceStatusResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalENDCResourceStatusResponseUnmarshalAPERWithOptions(v *ENDCResourceStatusResponse, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENDCResourceStatusResponse")
	}
	bb.EnterComponent("ENDCResourceStatusResponse")
	if err := X2apInternalENDCResourceStatusResponseUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "ENDCResourceStatusResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENDCResourceStatusResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENDCResourceStatusResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalENDCResourceStatusResponseUnmarshalAPERFrom(v *ENDCResourceStatusResponse, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCResourceStatusResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s06.ENDCResourceStatusResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s06.ENDCResourceStatusResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s06.X2apInternalENDCResourceStatusResponseIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes ENDCPartialResetConfirm to APER format.
func X2apInternalENDCPartialResetConfirmMarshalAPERLegacy(v *ENDCPartialResetConfirm) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalENDCPartialResetConfirmMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalENDCPartialResetConfirmMarshalAPERTo(v *ENDCPartialResetConfirm, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s18.X2apInternalENDCPartialResetConfirmIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ENDCPartialResetConfirm from APER format.
func X2apInternalENDCPartialResetConfirmUnmarshalAPERLegacy(v *ENDCPartialResetConfirm, data []byte) error {
	return X2apInternalENDCPartialResetConfirmUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENDCPartialResetConfirm with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalENDCPartialResetConfirmUnmarshalAPERWithOptions(v *ENDCPartialResetConfirm, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENDCPartialResetConfirm")
	}
	bb.EnterComponent("ENDCPartialResetConfirm")
	if err := X2apInternalENDCPartialResetConfirmUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "ENDCPartialResetConfirm")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENDCPartialResetConfirm")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENDCPartialResetConfirm")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalENDCPartialResetConfirmUnmarshalAPERFrom(v *ENDCPartialResetConfirm, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCPartialResetConfirm{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s18.ENDCPartialResetConfirmIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s18.ENDCPartialResetConfirmIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s18.X2apInternalENDCPartialResetConfirmIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes EUTRANRCellResourceCoordinationResponse to APER format.
func X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERLegacy(v *EUTRANRCellResourceCoordinationResponse) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERTo(v *EUTRANRCellResourceCoordinationResponse, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s16.X2apInternalEUTRANRCellResourceCoordinationResponseIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes EUTRANRCellResourceCoordinationResponse from APER format.
func X2apInternalEUTRANRCellResourceCoordinationResponseUnmarshalAPERLegacy(v *EUTRANRCellResourceCoordinationResponse, data []byte) error {
	return X2apInternalEUTRANRCellResourceCoordinationResponseUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes EUTRANRCellResourceCoordinationResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalEUTRANRCellResourceCoordinationResponseUnmarshalAPERWithOptions(v *EUTRANRCellResourceCoordinationResponse, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EUTRANRCellResourceCoordinationResponse")
	}
	bb.EnterComponent("EUTRANRCellResourceCoordinationResponse")
	if err := X2apInternalEUTRANRCellResourceCoordinationResponseUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "EUTRANRCellResourceCoordinationResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "EUTRANRCellResourceCoordinationResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "EUTRANRCellResourceCoordinationResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalEUTRANRCellResourceCoordinationResponseUnmarshalAPERFrom(v *EUTRANRCellResourceCoordinationResponse, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EUTRANRCellResourceCoordinationResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s16.EUTRANRCellResourceCoordinationResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s16.EUTRANRCellResourceCoordinationResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s16.X2apInternalEUTRANRCellResourceCoordinationResponseIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes ENDCX2RemovalResponse to APER format.
func X2apInternalENDCX2RemovalResponseMarshalAPERLegacy(v *ENDCX2RemovalResponse) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalENDCX2RemovalResponseMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalENDCX2RemovalResponseMarshalAPERTo(v *ENDCX2RemovalResponse, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s07.X2apInternalENDCX2RemovalResponseIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ENDCX2RemovalResponse from APER format.
func X2apInternalENDCX2RemovalResponseUnmarshalAPERLegacy(v *ENDCX2RemovalResponse, data []byte) error {
	return X2apInternalENDCX2RemovalResponseUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ENDCX2RemovalResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalENDCX2RemovalResponseUnmarshalAPERWithOptions(v *ENDCX2RemovalResponse, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ENDCX2RemovalResponse")
	}
	bb.EnterComponent("ENDCX2RemovalResponse")
	if err := X2apInternalENDCX2RemovalResponseUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "ENDCX2RemovalResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "ENDCX2RemovalResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "ENDCX2RemovalResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalENDCX2RemovalResponseUnmarshalAPERFrom(v *ENDCX2RemovalResponse, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ENDCX2RemovalResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s07.ENDCX2RemovalResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s07.ENDCX2RemovalResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s07.X2apInternalENDCX2RemovalResponseIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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

// MarshalAPER encodes UERadioCapabilityIDMappingResponse to APER format.
func X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERLegacy(v *UERadioCapabilityIDMappingResponse) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERTo(v *UERadioCapabilityIDMappingResponse, bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.stream.ReplayTo(bb); ok || err != nil {
			return err
		}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s00.X2apInternalPreferredSequenceTail(v.extPresent, v.extData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for _, present := range v.extPresent {
		hasExtensions = hasExtensions || present
	}
	for _, data := range v.extData {
		hasExtensions = hasExtensions || data != nil
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
			if err := s11.X2apInternalUERadioCapabilityIDMappingResponseIEFieldMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(v.extData)) && v.extData[i] != nil) {
				var data []byte
				if i < int64(len(v.extData)) {
					data = v.extData[i]
				}
				if err := aper.EncodeExtensionContents(bb, data, v.extWire, i); err != nil {
					return err
				}
			}
		}
	}
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes UERadioCapabilityIDMappingResponse from APER format.
func X2apInternalUERadioCapabilityIDMappingResponseUnmarshalAPERLegacy(v *UERadioCapabilityIDMappingResponse, data []byte) error {
	return X2apInternalUERadioCapabilityIDMappingResponseUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UERadioCapabilityIDMappingResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalUERadioCapabilityIDMappingResponseUnmarshalAPERWithOptions(v *UERadioCapabilityIDMappingResponse, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponse")
	}
	bb.EnterComponent("UERadioCapabilityIDMappingResponse")
	if err := X2apInternalUERadioCapabilityIDMappingResponseUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "UERadioCapabilityIDMappingResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func X2apInternalUERadioCapabilityIDMappingResponseUnmarshalAPERFrom(v *UERadioCapabilityIDMappingResponse, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UERadioCapabilityIDMappingResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s11.UERadioCapabilityIDMappingResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s11.UERadioCapabilityIDMappingResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s11.X2apInternalUERadioCapabilityIDMappingResponseIEFieldUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.CaptureOrigin()
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
func (v *CellActivationResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "CellActivationResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "CellActivationResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CellActivationResponse) WithoutReplay() CellActivationResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero CellActivationResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENBConfigurationUpdateAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "ENBConfigurationUpdateAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENBConfigurationUpdateAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENBConfigurationUpdateAcknowledge) WithoutReplay() ENBConfigurationUpdateAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENBConfigurationUpdateAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENDCCellActivationResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "ENDCCellActivationResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENDCCellActivationResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENDCCellActivationResponse) WithoutReplay() ENDCCellActivationResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENDCCellActivationResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENDCConfigurationUpdateAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "ENDCConfigurationUpdateAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENDCConfigurationUpdateAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENDCConfigurationUpdateAcknowledge) WithoutReplay() ENDCConfigurationUpdateAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENDCConfigurationUpdateAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENDCPartialResetConfirm) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "ENDCPartialResetConfirm", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENDCPartialResetConfirm", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENDCPartialResetConfirm) WithoutReplay() ENDCPartialResetConfirm {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENDCPartialResetConfirm
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENDCResourceStatusResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "ENDCResourceStatusResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENDCResourceStatusResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENDCResourceStatusResponse) WithoutReplay() ENDCResourceStatusResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENDCResourceStatusResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENDCX2RemovalResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "ENDCX2RemovalResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENDCX2RemovalResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENDCX2RemovalResponse) WithoutReplay() ENDCX2RemovalResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENDCX2RemovalResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ENDCX2SetupResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "ENDCX2SetupResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ENDCX2SetupResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ENDCX2SetupResponse) WithoutReplay() ENDCX2SetupResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ENDCX2SetupResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EUTRANRCellResourceCoordinationResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "EUTRANRCellResourceCoordinationResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "EUTRANRCellResourceCoordinationResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EUTRANRCellResourceCoordinationResponse) WithoutReplay() EUTRANRCellResourceCoordinationResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero EUTRANRCellResourceCoordinationResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *HandoverRequestAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "HandoverRequestAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "HandoverRequestAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v HandoverRequestAcknowledge) WithoutReplay() HandoverRequestAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero HandoverRequestAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MobilityChangeAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "MobilityChangeAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "MobilityChangeAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MobilityChangeAcknowledge) WithoutReplay() MobilityChangeAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero MobilityChangeAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResetResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "ResetResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ResetResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResetResponse) WithoutReplay() ResetResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ResetResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResourceStatusResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "ResourceStatusResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ResourceStatusResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResourceStatusResponse) WithoutReplay() ResourceStatusResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ResourceStatusResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RetrieveUEContextResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "RetrieveUEContextResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "RetrieveUEContextResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RetrieveUEContextResponse) WithoutReplay() RetrieveUEContextResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero RetrieveUEContextResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SeNBAdditionRequestAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "SeNBAdditionRequestAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SeNBAdditionRequestAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SeNBAdditionRequestAcknowledge) WithoutReplay() SeNBAdditionRequestAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SeNBAdditionRequestAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SeNBModificationConfirm) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "SeNBModificationConfirm", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SeNBModificationConfirm", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SeNBModificationConfirm) WithoutReplay() SeNBModificationConfirm {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SeNBModificationConfirm
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SeNBModificationRequestAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "SeNBModificationRequestAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SeNBModificationRequestAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SeNBModificationRequestAcknowledge) WithoutReplay() SeNBModificationRequestAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SeNBModificationRequestAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SeNBReleaseConfirm) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "SeNBReleaseConfirm", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SeNBReleaseConfirm", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SeNBReleaseConfirm) WithoutReplay() SeNBReleaseConfirm {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SeNBReleaseConfirm
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SgNBAdditionRequestAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "SgNBAdditionRequestAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SgNBAdditionRequestAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SgNBAdditionRequestAcknowledge) WithoutReplay() SgNBAdditionRequestAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SgNBAdditionRequestAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SgNBChangeConfirm) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "SgNBChangeConfirm", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SgNBChangeConfirm", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SgNBChangeConfirm) WithoutReplay() SgNBChangeConfirm {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SgNBChangeConfirm
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SgNBModificationConfirm) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "SgNBModificationConfirm", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SgNBModificationConfirm", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SgNBModificationConfirm) WithoutReplay() SgNBModificationConfirm {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SgNBModificationConfirm
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SgNBModificationRequestAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "SgNBModificationRequestAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SgNBModificationRequestAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SgNBModificationRequestAcknowledge) WithoutReplay() SgNBModificationRequestAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SgNBModificationRequestAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SgNBReleaseConfirm) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "SgNBReleaseConfirm", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SgNBReleaseConfirm", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SgNBReleaseConfirm) WithoutReplay() SgNBReleaseConfirm {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SgNBReleaseConfirm
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SgNBReleaseRequestAcknowledge) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "SgNBReleaseRequestAcknowledge", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "SgNBReleaseRequestAcknowledge", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SgNBReleaseRequestAcknowledge) WithoutReplay() SgNBReleaseRequestAcknowledge {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero SgNBReleaseRequestAcknowledge
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UERadioCapabilityIDMappingResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "UERadioCapabilityIDMappingResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UERadioCapabilityIDMappingResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UERadioCapabilityIDMappingResponse) WithoutReplay() UERadioCapabilityIDMappingResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UERadioCapabilityIDMappingResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *X2RemovalResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "X2RemovalResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "X2RemovalResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v X2RemovalResponse) WithoutReplay() X2RemovalResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero X2RemovalResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *X2SetupResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "X2SetupResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "X2SetupResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v X2SetupResponse) WithoutReplay() X2SetupResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero X2SetupResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *CellActivationResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *CellActivationResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellActivationResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellActivationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *CellActivationResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("CellActivationResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("CellActivationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENBConfigurationUpdateAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENBConfigurationUpdateAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENBConfigurationUpdateAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENBConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENBConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENDCCellActivationResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENDCCellActivationResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCCellActivationResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCCellActivationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENDCCellActivationResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCCellActivationResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCCellActivationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENDCConfigurationUpdateAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENDCConfigurationUpdateAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENDCConfigurationUpdateAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCConfigurationUpdateAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENDCPartialResetConfirm) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENDCPartialResetConfirm) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCPartialResetConfirm.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCPartialResetConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENDCPartialResetConfirm) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCPartialResetConfirm.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCPartialResetConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENDCResourceStatusResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENDCResourceStatusResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCResourceStatusResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCResourceStatusResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENDCResourceStatusResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCResourceStatusResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCResourceStatusResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENDCX2RemovalResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENDCX2RemovalResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCX2RemovalResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCX2RemovalResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENDCX2RemovalResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCX2RemovalResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCX2RemovalResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ENDCX2SetupResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ENDCX2SetupResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCX2SetupResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCX2SetupResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ENDCX2SetupResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ENDCX2SetupResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ENDCX2SetupResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *EUTRANRCellResourceCoordinationResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *EUTRANRCellResourceCoordinationResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EUTRANRCellResourceCoordinationResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EUTRANRCellResourceCoordinationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *EUTRANRCellResourceCoordinationResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EUTRANRCellResourceCoordinationResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EUTRANRCellResourceCoordinationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *HandoverRequestAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *HandoverRequestAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *HandoverRequestAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *MobilityChangeAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MobilityChangeAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MobilityChangeAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MobilityChangeAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MobilityChangeAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MobilityChangeAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MobilityChangeAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ResetResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResetResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResetResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResetResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResetResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResetResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResetResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ResourceStatusResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResourceStatusResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResourceStatusResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResourceStatusResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResourceStatusResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResourceStatusResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResourceStatusResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *RetrieveUEContextResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *RetrieveUEContextResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RetrieveUEContextResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RetrieveUEContextResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *RetrieveUEContextResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RetrieveUEContextResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RetrieveUEContextResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SeNBAdditionRequestAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SeNBAdditionRequestAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SeNBAdditionRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SeNBAdditionRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SeNBAdditionRequestAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SeNBAdditionRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SeNBAdditionRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SeNBModificationConfirm) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SeNBModificationConfirm) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SeNBModificationConfirm.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SeNBModificationConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SeNBModificationConfirm) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SeNBModificationConfirm.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SeNBModificationConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SeNBModificationRequestAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SeNBModificationRequestAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SeNBModificationRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SeNBModificationRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SeNBModificationRequestAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SeNBModificationRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SeNBModificationRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SeNBReleaseConfirm) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SeNBReleaseConfirm) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SeNBReleaseConfirm.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SeNBReleaseConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SeNBReleaseConfirm) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SeNBReleaseConfirm.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SeNBReleaseConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SgNBAdditionRequestAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SgNBAdditionRequestAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SgNBAdditionRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SgNBAdditionRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SgNBAdditionRequestAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SgNBAdditionRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SgNBAdditionRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SgNBChangeConfirm) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SgNBChangeConfirm) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SgNBChangeConfirm.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SgNBChangeConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SgNBChangeConfirm) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SgNBChangeConfirm.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SgNBChangeConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SgNBModificationConfirm) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SgNBModificationConfirm) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SgNBModificationConfirm.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SgNBModificationConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SgNBModificationConfirm) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SgNBModificationConfirm.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SgNBModificationConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SgNBModificationRequestAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SgNBModificationRequestAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SgNBModificationRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SgNBModificationRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SgNBModificationRequestAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SgNBModificationRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SgNBModificationRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SgNBReleaseConfirm) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SgNBReleaseConfirm) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SgNBReleaseConfirm.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SgNBReleaseConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SgNBReleaseConfirm) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SgNBReleaseConfirm.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SgNBReleaseConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SgNBReleaseRequestAcknowledge) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SgNBReleaseRequestAcknowledge) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SgNBReleaseRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SgNBReleaseRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SgNBReleaseRequestAcknowledge) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SgNBReleaseRequestAcknowledge.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SgNBReleaseRequestAcknowledge.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UERadioCapabilityIDMappingResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UERadioCapabilityIDMappingResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UERadioCapabilityIDMappingResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UERadioCapabilityIDMappingResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UERadioCapabilityIDMappingResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UERadioCapabilityIDMappingResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UERadioCapabilityIDMappingResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *X2RemovalResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *X2RemovalResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("X2RemovalResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("X2RemovalResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *X2RemovalResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("X2RemovalResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("X2RemovalResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *X2SetupResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *X2SetupResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("X2SetupResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("X2SetupResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *X2SetupResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("X2SetupResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("X2SetupResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *CellActivationResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "CellActivationResponse")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "CellActivationResponse")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APCellActivationResponse(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "CellActivationResponse")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "CellActivationResponse")
		}
		return X2apInternalCellActivationResponseMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalCellActivationResponseMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalCellActivationResponseMarshalAPERWithPlan(v *CellActivationResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalCellActivationResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "CellActivationResponse")
}
func X2apInternalCellActivationResponseMarshalAPERUnplanned(v *CellActivationResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalCellActivationResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "CellActivationResponse")
}
func X2apInternalCellActivationResponseMarshalAPERBudget(v *CellActivationResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APCellActivationResponse(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalCellActivationResponseMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalCellActivationResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalCellActivationResponseMarshalAPERChanged(v *CellActivationResponse, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalCellActivationResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalCellActivationResponseMarshalAPERPlanned(v *CellActivationResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalCellActivationResponseMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *ENBConfigurationUpdateAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENBConfigurationUpdateAcknowledge")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APENBConfigurationUpdateAcknowledge(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
		}
		return X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERWithPlan(v *ENBConfigurationUpdateAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
}
func X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERUnplanned(v *ENBConfigurationUpdateAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
}
func X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERBudget(v *ENBConfigurationUpdateAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APENBConfigurationUpdateAcknowledge(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERChanged(v *ENBConfigurationUpdateAcknowledge, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERPlanned(v *ENBConfigurationUpdateAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalENBConfigurationUpdateAcknowledgeMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *ENDCCellActivationResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENDCCellActivationResponse")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENDCCellActivationResponse")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APENDCCellActivationResponse(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "ENDCCellActivationResponse")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "ENDCCellActivationResponse")
		}
		return X2apInternalENDCCellActivationResponseMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalENDCCellActivationResponseMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalENDCCellActivationResponseMarshalAPERWithPlan(v *ENDCCellActivationResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalENDCCellActivationResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ENDCCellActivationResponse")
}
func X2apInternalENDCCellActivationResponseMarshalAPERUnplanned(v *ENDCCellActivationResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalENDCCellActivationResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ENDCCellActivationResponse")
}
func X2apInternalENDCCellActivationResponseMarshalAPERBudget(v *ENDCCellActivationResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APENDCCellActivationResponse(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalENDCCellActivationResponseMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalENDCCellActivationResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalENDCCellActivationResponseMarshalAPERChanged(v *ENDCCellActivationResponse, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalENDCCellActivationResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalENDCCellActivationResponseMarshalAPERPlanned(v *ENDCCellActivationResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalENDCCellActivationResponseMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *ENDCConfigurationUpdateAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENDCConfigurationUpdateAcknowledge")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENDCConfigurationUpdateAcknowledge")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APENDCConfigurationUpdateAcknowledge(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "ENDCConfigurationUpdateAcknowledge")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "ENDCConfigurationUpdateAcknowledge")
		}
		return X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERWithPlan(v *ENDCConfigurationUpdateAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ENDCConfigurationUpdateAcknowledge")
}
func X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERUnplanned(v *ENDCConfigurationUpdateAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ENDCConfigurationUpdateAcknowledge")
}
func X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERBudget(v *ENDCConfigurationUpdateAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APENDCConfigurationUpdateAcknowledge(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERChanged(v *ENDCConfigurationUpdateAcknowledge, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERPlanned(v *ENDCConfigurationUpdateAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalENDCConfigurationUpdateAcknowledgeMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *ENDCPartialResetConfirm) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENDCPartialResetConfirm")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENDCPartialResetConfirm")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APENDCPartialResetConfirm(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "ENDCPartialResetConfirm")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "ENDCPartialResetConfirm")
		}
		return X2apInternalENDCPartialResetConfirmMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalENDCPartialResetConfirmMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalENDCPartialResetConfirmMarshalAPERWithPlan(v *ENDCPartialResetConfirm, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalENDCPartialResetConfirmMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ENDCPartialResetConfirm")
}
func X2apInternalENDCPartialResetConfirmMarshalAPERUnplanned(v *ENDCPartialResetConfirm, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalENDCPartialResetConfirmMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ENDCPartialResetConfirm")
}
func X2apInternalENDCPartialResetConfirmMarshalAPERBudget(v *ENDCPartialResetConfirm, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APENDCPartialResetConfirm(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalENDCPartialResetConfirmMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalENDCPartialResetConfirmMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalENDCPartialResetConfirmMarshalAPERChanged(v *ENDCPartialResetConfirm, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalENDCPartialResetConfirmMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalENDCPartialResetConfirmMarshalAPERPlanned(v *ENDCPartialResetConfirm, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalENDCPartialResetConfirmMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *ENDCResourceStatusResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENDCResourceStatusResponse")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENDCResourceStatusResponse")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APENDCResourceStatusResponse(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "ENDCResourceStatusResponse")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "ENDCResourceStatusResponse")
		}
		return X2apInternalENDCResourceStatusResponseMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalENDCResourceStatusResponseMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalENDCResourceStatusResponseMarshalAPERWithPlan(v *ENDCResourceStatusResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalENDCResourceStatusResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ENDCResourceStatusResponse")
}
func X2apInternalENDCResourceStatusResponseMarshalAPERUnplanned(v *ENDCResourceStatusResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalENDCResourceStatusResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ENDCResourceStatusResponse")
}
func X2apInternalENDCResourceStatusResponseMarshalAPERBudget(v *ENDCResourceStatusResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APENDCResourceStatusResponse(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalENDCResourceStatusResponseMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalENDCResourceStatusResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalENDCResourceStatusResponseMarshalAPERChanged(v *ENDCResourceStatusResponse, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalENDCResourceStatusResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalENDCResourceStatusResponseMarshalAPERPlanned(v *ENDCResourceStatusResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalENDCResourceStatusResponseMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *ENDCX2RemovalResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENDCX2RemovalResponse")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENDCX2RemovalResponse")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APENDCX2RemovalResponse(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "ENDCX2RemovalResponse")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "ENDCX2RemovalResponse")
		}
		return X2apInternalENDCX2RemovalResponseMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalENDCX2RemovalResponseMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalENDCX2RemovalResponseMarshalAPERWithPlan(v *ENDCX2RemovalResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalENDCX2RemovalResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ENDCX2RemovalResponse")
}
func X2apInternalENDCX2RemovalResponseMarshalAPERUnplanned(v *ENDCX2RemovalResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalENDCX2RemovalResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ENDCX2RemovalResponse")
}
func X2apInternalENDCX2RemovalResponseMarshalAPERBudget(v *ENDCX2RemovalResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APENDCX2RemovalResponse(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalENDCX2RemovalResponseMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalENDCX2RemovalResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalENDCX2RemovalResponseMarshalAPERChanged(v *ENDCX2RemovalResponse, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalENDCX2RemovalResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalENDCX2RemovalResponseMarshalAPERPlanned(v *ENDCX2RemovalResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalENDCX2RemovalResponseMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *ENDCX2SetupResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ENDCX2SetupResponse")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ENDCX2SetupResponse")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APENDCX2SetupResponse(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "ENDCX2SetupResponse")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "ENDCX2SetupResponse")
		}
		return X2apInternalENDCX2SetupResponseMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalENDCX2SetupResponseMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalENDCX2SetupResponseMarshalAPERWithPlan(v *ENDCX2SetupResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalENDCX2SetupResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ENDCX2SetupResponse")
}
func X2apInternalENDCX2SetupResponseMarshalAPERUnplanned(v *ENDCX2SetupResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalENDCX2SetupResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ENDCX2SetupResponse")
}
func X2apInternalENDCX2SetupResponseMarshalAPERBudget(v *ENDCX2SetupResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APENDCX2SetupResponse(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalENDCX2SetupResponseMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalENDCX2SetupResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalENDCX2SetupResponseMarshalAPERChanged(v *ENDCX2SetupResponse, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalENDCX2SetupResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalENDCX2SetupResponseMarshalAPERPlanned(v *ENDCX2SetupResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalENDCX2SetupResponseMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *EUTRANRCellResourceCoordinationResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EUTRANRCellResourceCoordinationResponse")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "EUTRANRCellResourceCoordinationResponse")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APEUTRANRCellResourceCoordinationResponse(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "EUTRANRCellResourceCoordinationResponse")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "EUTRANRCellResourceCoordinationResponse")
		}
		return X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERWithPlan(v *EUTRANRCellResourceCoordinationResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "EUTRANRCellResourceCoordinationResponse")
}
func X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERUnplanned(v *EUTRANRCellResourceCoordinationResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "EUTRANRCellResourceCoordinationResponse")
}
func X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERBudget(v *EUTRANRCellResourceCoordinationResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APEUTRANRCellResourceCoordinationResponse(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERChanged(v *EUTRANRCellResourceCoordinationResponse, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERPlanned(v *EUTRANRCellResourceCoordinationResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalEUTRANRCellResourceCoordinationResponseMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *HandoverRequestAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "HandoverRequestAcknowledge")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "HandoverRequestAcknowledge")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APHandoverRequestAcknowledge(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "HandoverRequestAcknowledge")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "HandoverRequestAcknowledge")
		}
		return X2apInternalHandoverRequestAcknowledgeMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalHandoverRequestAcknowledgeMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalHandoverRequestAcknowledgeMarshalAPERWithPlan(v *HandoverRequestAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalHandoverRequestAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "HandoverRequestAcknowledge")
}
func X2apInternalHandoverRequestAcknowledgeMarshalAPERUnplanned(v *HandoverRequestAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalHandoverRequestAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "HandoverRequestAcknowledge")
}
func X2apInternalHandoverRequestAcknowledgeMarshalAPERBudget(v *HandoverRequestAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APHandoverRequestAcknowledge(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalHandoverRequestAcknowledgeMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalHandoverRequestAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalHandoverRequestAcknowledgeMarshalAPERChanged(v *HandoverRequestAcknowledge, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalHandoverRequestAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalHandoverRequestAcknowledgeMarshalAPERPlanned(v *HandoverRequestAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalHandoverRequestAcknowledgeMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *MobilityChangeAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MobilityChangeAcknowledge")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "MobilityChangeAcknowledge")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APMobilityChangeAcknowledge(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "MobilityChangeAcknowledge")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "MobilityChangeAcknowledge")
		}
		return X2apInternalMobilityChangeAcknowledgeMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalMobilityChangeAcknowledgeMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalMobilityChangeAcknowledgeMarshalAPERWithPlan(v *MobilityChangeAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalMobilityChangeAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "MobilityChangeAcknowledge")
}
func X2apInternalMobilityChangeAcknowledgeMarshalAPERUnplanned(v *MobilityChangeAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalMobilityChangeAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "MobilityChangeAcknowledge")
}
func X2apInternalMobilityChangeAcknowledgeMarshalAPERBudget(v *MobilityChangeAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APMobilityChangeAcknowledge(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalMobilityChangeAcknowledgeMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalMobilityChangeAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalMobilityChangeAcknowledgeMarshalAPERChanged(v *MobilityChangeAcknowledge, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalMobilityChangeAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalMobilityChangeAcknowledgeMarshalAPERPlanned(v *MobilityChangeAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalMobilityChangeAcknowledgeMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *ResetResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResetResponse")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ResetResponse")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APResetResponse(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "ResetResponse")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "ResetResponse")
		}
		return X2apInternalResetResponseMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalResetResponseMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalResetResponseMarshalAPERWithPlan(v *ResetResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalResetResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ResetResponse")
}
func X2apInternalResetResponseMarshalAPERUnplanned(v *ResetResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalResetResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ResetResponse")
}
func X2apInternalResetResponseMarshalAPERBudget(v *ResetResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APResetResponse(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalResetResponseMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalResetResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalResetResponseMarshalAPERChanged(v *ResetResponse, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalResetResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalResetResponseMarshalAPERPlanned(v *ResetResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalResetResponseMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *ResourceStatusResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResourceStatusResponse")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ResourceStatusResponse")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APResourceStatusResponse(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "ResourceStatusResponse")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "ResourceStatusResponse")
		}
		return X2apInternalResourceStatusResponseMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalResourceStatusResponseMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalResourceStatusResponseMarshalAPERWithPlan(v *ResourceStatusResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalResourceStatusResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ResourceStatusResponse")
}
func X2apInternalResourceStatusResponseMarshalAPERUnplanned(v *ResourceStatusResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalResourceStatusResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ResourceStatusResponse")
}
func X2apInternalResourceStatusResponseMarshalAPERBudget(v *ResourceStatusResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APResourceStatusResponse(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalResourceStatusResponseMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalResourceStatusResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalResourceStatusResponseMarshalAPERChanged(v *ResourceStatusResponse, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalResourceStatusResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalResourceStatusResponseMarshalAPERPlanned(v *ResourceStatusResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalResourceStatusResponseMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *RetrieveUEContextResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RetrieveUEContextResponse")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "RetrieveUEContextResponse")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APRetrieveUEContextResponse(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "RetrieveUEContextResponse")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "RetrieveUEContextResponse")
		}
		return X2apInternalRetrieveUEContextResponseMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalRetrieveUEContextResponseMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalRetrieveUEContextResponseMarshalAPERWithPlan(v *RetrieveUEContextResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalRetrieveUEContextResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "RetrieveUEContextResponse")
}
func X2apInternalRetrieveUEContextResponseMarshalAPERUnplanned(v *RetrieveUEContextResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalRetrieveUEContextResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "RetrieveUEContextResponse")
}
func X2apInternalRetrieveUEContextResponseMarshalAPERBudget(v *RetrieveUEContextResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APRetrieveUEContextResponse(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalRetrieveUEContextResponseMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalRetrieveUEContextResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalRetrieveUEContextResponseMarshalAPERChanged(v *RetrieveUEContextResponse, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalRetrieveUEContextResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalRetrieveUEContextResponseMarshalAPERPlanned(v *RetrieveUEContextResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalRetrieveUEContextResponseMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *SeNBAdditionRequestAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SeNBAdditionRequestAcknowledge")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SeNBAdditionRequestAcknowledge")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APSeNBAdditionRequestAcknowledge(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "SeNBAdditionRequestAcknowledge")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "SeNBAdditionRequestAcknowledge")
		}
		return X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERWithPlan(v *SeNBAdditionRequestAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SeNBAdditionRequestAcknowledge")
}
func X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERUnplanned(v *SeNBAdditionRequestAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SeNBAdditionRequestAcknowledge")
}
func X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERBudget(v *SeNBAdditionRequestAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APSeNBAdditionRequestAcknowledge(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERChanged(v *SeNBAdditionRequestAcknowledge, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERPlanned(v *SeNBAdditionRequestAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalSeNBAdditionRequestAcknowledgeMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *SeNBModificationConfirm) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SeNBModificationConfirm")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SeNBModificationConfirm")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APSeNBModificationConfirm(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "SeNBModificationConfirm")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "SeNBModificationConfirm")
		}
		return X2apInternalSeNBModificationConfirmMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalSeNBModificationConfirmMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalSeNBModificationConfirmMarshalAPERWithPlan(v *SeNBModificationConfirm, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalSeNBModificationConfirmMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SeNBModificationConfirm")
}
func X2apInternalSeNBModificationConfirmMarshalAPERUnplanned(v *SeNBModificationConfirm, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalSeNBModificationConfirmMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SeNBModificationConfirm")
}
func X2apInternalSeNBModificationConfirmMarshalAPERBudget(v *SeNBModificationConfirm, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APSeNBModificationConfirm(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalSeNBModificationConfirmMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalSeNBModificationConfirmMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSeNBModificationConfirmMarshalAPERChanged(v *SeNBModificationConfirm, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalSeNBModificationConfirmMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSeNBModificationConfirmMarshalAPERPlanned(v *SeNBModificationConfirm, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalSeNBModificationConfirmMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *SeNBModificationRequestAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SeNBModificationRequestAcknowledge")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SeNBModificationRequestAcknowledge")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APSeNBModificationRequestAcknowledge(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "SeNBModificationRequestAcknowledge")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "SeNBModificationRequestAcknowledge")
		}
		return X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERWithPlan(v *SeNBModificationRequestAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SeNBModificationRequestAcknowledge")
}
func X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERUnplanned(v *SeNBModificationRequestAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SeNBModificationRequestAcknowledge")
}
func X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERBudget(v *SeNBModificationRequestAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APSeNBModificationRequestAcknowledge(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERChanged(v *SeNBModificationRequestAcknowledge, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERPlanned(v *SeNBModificationRequestAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalSeNBModificationRequestAcknowledgeMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *SeNBReleaseConfirm) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SeNBReleaseConfirm")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SeNBReleaseConfirm")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APSeNBReleaseConfirm(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "SeNBReleaseConfirm")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "SeNBReleaseConfirm")
		}
		return X2apInternalSeNBReleaseConfirmMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalSeNBReleaseConfirmMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalSeNBReleaseConfirmMarshalAPERWithPlan(v *SeNBReleaseConfirm, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalSeNBReleaseConfirmMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SeNBReleaseConfirm")
}
func X2apInternalSeNBReleaseConfirmMarshalAPERUnplanned(v *SeNBReleaseConfirm, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalSeNBReleaseConfirmMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SeNBReleaseConfirm")
}
func X2apInternalSeNBReleaseConfirmMarshalAPERBudget(v *SeNBReleaseConfirm, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APSeNBReleaseConfirm(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalSeNBReleaseConfirmMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalSeNBReleaseConfirmMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSeNBReleaseConfirmMarshalAPERChanged(v *SeNBReleaseConfirm, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalSeNBReleaseConfirmMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSeNBReleaseConfirmMarshalAPERPlanned(v *SeNBReleaseConfirm, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalSeNBReleaseConfirmMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *SgNBAdditionRequestAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SgNBAdditionRequestAcknowledge")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SgNBAdditionRequestAcknowledge")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APSgNBAdditionRequestAcknowledge(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "SgNBAdditionRequestAcknowledge")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "SgNBAdditionRequestAcknowledge")
		}
		return X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERWithPlan(v *SgNBAdditionRequestAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SgNBAdditionRequestAcknowledge")
}
func X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERUnplanned(v *SgNBAdditionRequestAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SgNBAdditionRequestAcknowledge")
}
func X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERBudget(v *SgNBAdditionRequestAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APSgNBAdditionRequestAcknowledge(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERChanged(v *SgNBAdditionRequestAcknowledge, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERPlanned(v *SgNBAdditionRequestAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalSgNBAdditionRequestAcknowledgeMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *SgNBChangeConfirm) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SgNBChangeConfirm")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SgNBChangeConfirm")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APSgNBChangeConfirm(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "SgNBChangeConfirm")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "SgNBChangeConfirm")
		}
		return X2apInternalSgNBChangeConfirmMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalSgNBChangeConfirmMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalSgNBChangeConfirmMarshalAPERWithPlan(v *SgNBChangeConfirm, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalSgNBChangeConfirmMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SgNBChangeConfirm")
}
func X2apInternalSgNBChangeConfirmMarshalAPERUnplanned(v *SgNBChangeConfirm, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalSgNBChangeConfirmMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SgNBChangeConfirm")
}
func X2apInternalSgNBChangeConfirmMarshalAPERBudget(v *SgNBChangeConfirm, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APSgNBChangeConfirm(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalSgNBChangeConfirmMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalSgNBChangeConfirmMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSgNBChangeConfirmMarshalAPERChanged(v *SgNBChangeConfirm, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalSgNBChangeConfirmMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSgNBChangeConfirmMarshalAPERPlanned(v *SgNBChangeConfirm, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalSgNBChangeConfirmMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *SgNBModificationConfirm) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SgNBModificationConfirm")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SgNBModificationConfirm")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APSgNBModificationConfirm(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "SgNBModificationConfirm")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "SgNBModificationConfirm")
		}
		return X2apInternalSgNBModificationConfirmMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalSgNBModificationConfirmMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalSgNBModificationConfirmMarshalAPERWithPlan(v *SgNBModificationConfirm, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalSgNBModificationConfirmMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SgNBModificationConfirm")
}
func X2apInternalSgNBModificationConfirmMarshalAPERUnplanned(v *SgNBModificationConfirm, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalSgNBModificationConfirmMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SgNBModificationConfirm")
}
func X2apInternalSgNBModificationConfirmMarshalAPERBudget(v *SgNBModificationConfirm, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APSgNBModificationConfirm(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalSgNBModificationConfirmMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalSgNBModificationConfirmMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSgNBModificationConfirmMarshalAPERChanged(v *SgNBModificationConfirm, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalSgNBModificationConfirmMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSgNBModificationConfirmMarshalAPERPlanned(v *SgNBModificationConfirm, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalSgNBModificationConfirmMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *SgNBModificationRequestAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SgNBModificationRequestAcknowledge")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SgNBModificationRequestAcknowledge")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APSgNBModificationRequestAcknowledge(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "SgNBModificationRequestAcknowledge")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "SgNBModificationRequestAcknowledge")
		}
		return X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERWithPlan(v *SgNBModificationRequestAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SgNBModificationRequestAcknowledge")
}
func X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERUnplanned(v *SgNBModificationRequestAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SgNBModificationRequestAcknowledge")
}
func X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERBudget(v *SgNBModificationRequestAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APSgNBModificationRequestAcknowledge(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERChanged(v *SgNBModificationRequestAcknowledge, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERPlanned(v *SgNBModificationRequestAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalSgNBModificationRequestAcknowledgeMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *SgNBReleaseConfirm) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SgNBReleaseConfirm")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SgNBReleaseConfirm")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APSgNBReleaseConfirm(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "SgNBReleaseConfirm")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "SgNBReleaseConfirm")
		}
		return X2apInternalSgNBReleaseConfirmMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalSgNBReleaseConfirmMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalSgNBReleaseConfirmMarshalAPERWithPlan(v *SgNBReleaseConfirm, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalSgNBReleaseConfirmMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SgNBReleaseConfirm")
}
func X2apInternalSgNBReleaseConfirmMarshalAPERUnplanned(v *SgNBReleaseConfirm, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalSgNBReleaseConfirmMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SgNBReleaseConfirm")
}
func X2apInternalSgNBReleaseConfirmMarshalAPERBudget(v *SgNBReleaseConfirm, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APSgNBReleaseConfirm(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalSgNBReleaseConfirmMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalSgNBReleaseConfirmMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSgNBReleaseConfirmMarshalAPERChanged(v *SgNBReleaseConfirm, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalSgNBReleaseConfirmMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSgNBReleaseConfirmMarshalAPERPlanned(v *SgNBReleaseConfirm, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalSgNBReleaseConfirmMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *SgNBReleaseRequestAcknowledge) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SgNBReleaseRequestAcknowledge")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SgNBReleaseRequestAcknowledge")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APSgNBReleaseRequestAcknowledge(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "SgNBReleaseRequestAcknowledge")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "SgNBReleaseRequestAcknowledge")
		}
		return X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERWithPlan(v *SgNBReleaseRequestAcknowledge, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SgNBReleaseRequestAcknowledge")
}
func X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERUnplanned(v *SgNBReleaseRequestAcknowledge, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SgNBReleaseRequestAcknowledge")
}
func X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERBudget(v *SgNBReleaseRequestAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APSgNBReleaseRequestAcknowledge(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERChanged(v *SgNBReleaseRequestAcknowledge, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERPlanned(v *SgNBReleaseRequestAcknowledge, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *UERadioCapabilityIDMappingResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UERadioCapabilityIDMappingResponse")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APUERadioCapabilityIDMappingResponse(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
		}
		return X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERWithPlan(v *UERadioCapabilityIDMappingResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
}
func X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERUnplanned(v *UERadioCapabilityIDMappingResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
}
func X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERBudget(v *UERadioCapabilityIDMappingResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APUERadioCapabilityIDMappingResponse(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERChanged(v *UERadioCapabilityIDMappingResponse, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERPlanned(v *UERadioCapabilityIDMappingResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *X2RemovalResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "X2RemovalResponse")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "X2RemovalResponse")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APX2RemovalResponse(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "X2RemovalResponse")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "X2RemovalResponse")
		}
		return X2apInternalX2RemovalResponseMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalX2RemovalResponseMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalX2RemovalResponseMarshalAPERWithPlan(v *X2RemovalResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalX2RemovalResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "X2RemovalResponse")
}
func X2apInternalX2RemovalResponseMarshalAPERUnplanned(v *X2RemovalResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalX2RemovalResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "X2RemovalResponse")
}
func X2apInternalX2RemovalResponseMarshalAPERBudget(v *X2RemovalResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APX2RemovalResponse(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalX2RemovalResponseMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalX2RemovalResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalX2RemovalResponseMarshalAPERChanged(v *X2RemovalResponse, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalX2RemovalResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalX2RemovalResponseMarshalAPERPlanned(v *X2RemovalResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalX2RemovalResponseMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *X2SetupResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "X2SetupResponse")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "X2SetupResponse")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APX2SetupResponse(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "X2SetupResponse")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "X2SetupResponse")
		}
		return X2apInternalX2SetupResponseMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalX2SetupResponseMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalX2SetupResponseMarshalAPERWithPlan(v *X2SetupResponse, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalX2SetupResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "X2SetupResponse")
}
func X2apInternalX2SetupResponseMarshalAPERUnplanned(v *X2SetupResponse, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalX2SetupResponseMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "X2SetupResponse")
}
func X2apInternalX2SetupResponseMarshalAPERBudget(v *X2SetupResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APX2SetupResponse(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalX2SetupResponseMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalX2SetupResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalX2SetupResponseMarshalAPERChanged(v *X2SetupResponse, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalX2SetupResponseMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalX2SetupResponseMarshalAPERPlanned(v *X2SetupResponse, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalX2SetupResponseMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *CellActivationResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "CellActivationResponse")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded CellActivationResponse
	err := X2apInternalCellActivationResponseUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APCellActivationResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = CellActivationResponse{}
		return report, aper.OperationError(err, "CellActivationResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "CellActivationResponse")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *ENBConfigurationUpdateAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENBConfigurationUpdateAcknowledge")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded ENBConfigurationUpdateAcknowledge
	err := X2apInternalENBConfigurationUpdateAcknowledgeUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APENBConfigurationUpdateAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ENBConfigurationUpdateAcknowledge{}
		return report, aper.OperationError(err, "ENBConfigurationUpdateAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENBConfigurationUpdateAcknowledge")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *ENDCCellActivationResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENDCCellActivationResponse")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded ENDCCellActivationResponse
	err := X2apInternalENDCCellActivationResponseUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APENDCCellActivationResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ENDCCellActivationResponse{}
		return report, aper.OperationError(err, "ENDCCellActivationResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENDCCellActivationResponse")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *ENDCConfigurationUpdateAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENDCConfigurationUpdateAcknowledge")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded ENDCConfigurationUpdateAcknowledge
	err := X2apInternalENDCConfigurationUpdateAcknowledgeUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APENDCConfigurationUpdateAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ENDCConfigurationUpdateAcknowledge{}
		return report, aper.OperationError(err, "ENDCConfigurationUpdateAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENDCConfigurationUpdateAcknowledge")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *ENDCPartialResetConfirm) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENDCPartialResetConfirm")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded ENDCPartialResetConfirm
	err := X2apInternalENDCPartialResetConfirmUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APENDCPartialResetConfirm(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ENDCPartialResetConfirm{}
		return report, aper.OperationError(err, "ENDCPartialResetConfirm")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENDCPartialResetConfirm")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *ENDCResourceStatusResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENDCResourceStatusResponse")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded ENDCResourceStatusResponse
	err := X2apInternalENDCResourceStatusResponseUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APENDCResourceStatusResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ENDCResourceStatusResponse{}
		return report, aper.OperationError(err, "ENDCResourceStatusResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENDCResourceStatusResponse")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *ENDCX2RemovalResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENDCX2RemovalResponse")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded ENDCX2RemovalResponse
	err := X2apInternalENDCX2RemovalResponseUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APENDCX2RemovalResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ENDCX2RemovalResponse{}
		return report, aper.OperationError(err, "ENDCX2RemovalResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENDCX2RemovalResponse")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *ENDCX2SetupResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ENDCX2SetupResponse")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded ENDCX2SetupResponse
	err := X2apInternalENDCX2SetupResponseUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APENDCX2SetupResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ENDCX2SetupResponse{}
		return report, aper.OperationError(err, "ENDCX2SetupResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ENDCX2SetupResponse")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *EUTRANRCellResourceCoordinationResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EUTRANRCellResourceCoordinationResponse")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded EUTRANRCellResourceCoordinationResponse
	err := X2apInternalEUTRANRCellResourceCoordinationResponseUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APEUTRANRCellResourceCoordinationResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = EUTRANRCellResourceCoordinationResponse{}
		return report, aper.OperationError(err, "EUTRANRCellResourceCoordinationResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EUTRANRCellResourceCoordinationResponse")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *HandoverRequestAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "HandoverRequestAcknowledge")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded HandoverRequestAcknowledge
	err := X2apInternalHandoverRequestAcknowledgeUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APHandoverRequestAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = HandoverRequestAcknowledge{}
		return report, aper.OperationError(err, "HandoverRequestAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "HandoverRequestAcknowledge")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *MobilityChangeAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MobilityChangeAcknowledge")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded MobilityChangeAcknowledge
	err := X2apInternalMobilityChangeAcknowledgeUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APMobilityChangeAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = MobilityChangeAcknowledge{}
		return report, aper.OperationError(err, "MobilityChangeAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MobilityChangeAcknowledge")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *ResetResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResetResponse")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded ResetResponse
	err := X2apInternalResetResponseUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APResetResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ResetResponse{}
		return report, aper.OperationError(err, "ResetResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResetResponse")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *ResourceStatusResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResourceStatusResponse")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded ResourceStatusResponse
	err := X2apInternalResourceStatusResponseUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APResourceStatusResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ResourceStatusResponse{}
		return report, aper.OperationError(err, "ResourceStatusResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResourceStatusResponse")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *RetrieveUEContextResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RetrieveUEContextResponse")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded RetrieveUEContextResponse
	err := X2apInternalRetrieveUEContextResponseUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APRetrieveUEContextResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = RetrieveUEContextResponse{}
		return report, aper.OperationError(err, "RetrieveUEContextResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RetrieveUEContextResponse")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *SeNBAdditionRequestAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SeNBAdditionRequestAcknowledge")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded SeNBAdditionRequestAcknowledge
	err := X2apInternalSeNBAdditionRequestAcknowledgeUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APSeNBAdditionRequestAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SeNBAdditionRequestAcknowledge{}
		return report, aper.OperationError(err, "SeNBAdditionRequestAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SeNBAdditionRequestAcknowledge")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *SeNBModificationConfirm) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SeNBModificationConfirm")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded SeNBModificationConfirm
	err := X2apInternalSeNBModificationConfirmUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APSeNBModificationConfirm(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SeNBModificationConfirm{}
		return report, aper.OperationError(err, "SeNBModificationConfirm")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SeNBModificationConfirm")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *SeNBModificationRequestAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SeNBModificationRequestAcknowledge")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded SeNBModificationRequestAcknowledge
	err := X2apInternalSeNBModificationRequestAcknowledgeUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APSeNBModificationRequestAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SeNBModificationRequestAcknowledge{}
		return report, aper.OperationError(err, "SeNBModificationRequestAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SeNBModificationRequestAcknowledge")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *SeNBReleaseConfirm) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SeNBReleaseConfirm")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded SeNBReleaseConfirm
	err := X2apInternalSeNBReleaseConfirmUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APSeNBReleaseConfirm(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SeNBReleaseConfirm{}
		return report, aper.OperationError(err, "SeNBReleaseConfirm")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SeNBReleaseConfirm")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *SgNBAdditionRequestAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SgNBAdditionRequestAcknowledge")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded SgNBAdditionRequestAcknowledge
	err := X2apInternalSgNBAdditionRequestAcknowledgeUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APSgNBAdditionRequestAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SgNBAdditionRequestAcknowledge{}
		return report, aper.OperationError(err, "SgNBAdditionRequestAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SgNBAdditionRequestAcknowledge")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *SgNBChangeConfirm) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SgNBChangeConfirm")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded SgNBChangeConfirm
	err := X2apInternalSgNBChangeConfirmUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APSgNBChangeConfirm(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SgNBChangeConfirm{}
		return report, aper.OperationError(err, "SgNBChangeConfirm")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SgNBChangeConfirm")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *SgNBModificationConfirm) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SgNBModificationConfirm")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded SgNBModificationConfirm
	err := X2apInternalSgNBModificationConfirmUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APSgNBModificationConfirm(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SgNBModificationConfirm{}
		return report, aper.OperationError(err, "SgNBModificationConfirm")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SgNBModificationConfirm")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *SgNBModificationRequestAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SgNBModificationRequestAcknowledge")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded SgNBModificationRequestAcknowledge
	err := X2apInternalSgNBModificationRequestAcknowledgeUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APSgNBModificationRequestAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SgNBModificationRequestAcknowledge{}
		return report, aper.OperationError(err, "SgNBModificationRequestAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SgNBModificationRequestAcknowledge")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *SgNBReleaseConfirm) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SgNBReleaseConfirm")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded SgNBReleaseConfirm
	err := X2apInternalSgNBReleaseConfirmUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APSgNBReleaseConfirm(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SgNBReleaseConfirm{}
		return report, aper.OperationError(err, "SgNBReleaseConfirm")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SgNBReleaseConfirm")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *SgNBReleaseRequestAcknowledge) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SgNBReleaseRequestAcknowledge")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded SgNBReleaseRequestAcknowledge
	err := X2apInternalSgNBReleaseRequestAcknowledgeUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APSgNBReleaseRequestAcknowledge(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SgNBReleaseRequestAcknowledge{}
		return report, aper.OperationError(err, "SgNBReleaseRequestAcknowledge")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SgNBReleaseRequestAcknowledge")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *UERadioCapabilityIDMappingResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UERadioCapabilityIDMappingResponse")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded UERadioCapabilityIDMappingResponse
	err := X2apInternalUERadioCapabilityIDMappingResponseUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APUERadioCapabilityIDMappingResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = UERadioCapabilityIDMappingResponse{}
		return report, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UERadioCapabilityIDMappingResponse")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *X2RemovalResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "X2RemovalResponse")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded X2RemovalResponse
	err := X2apInternalX2RemovalResponseUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APX2RemovalResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = X2RemovalResponse{}
		return report, aper.OperationError(err, "X2RemovalResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "X2RemovalResponse")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *X2SetupResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "X2SetupResponse")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded X2SetupResponse
	err := X2apInternalX2SetupResponseUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APX2SetupResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = X2SetupResponse{}
		return report, aper.OperationError(err, "X2SetupResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "X2SetupResponse")
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
func X2apInternalSuccessfulOutcomeMarshalAPERLegacy(v *SuccessfulOutcome) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalSuccessfulOutcomeMarshalAPERTo(v, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func X2apInternalSuccessfulOutcomeMarshalAPERTo(v *SuccessfulOutcome, bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.ProcedureCode), s00.X2apInternalInt64Ptr(0), s00.X2apInternalInt64Ptr(255), false); err != nil {
		return fmt.Errorf("encoding procedureCode: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	openData_value, err := X2apInternalSuccessfulValueEncodeFresh(v.Value, len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, openData_value); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes SuccessfulOutcome from APER format.
func X2apInternalSuccessfulOutcomeUnmarshalAPERLegacy(v *SuccessfulOutcome, data []byte) error {
	return X2apInternalSuccessfulOutcomeUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SuccessfulOutcome with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func X2apInternalSuccessfulOutcomeUnmarshalAPERWithOptions(v *SuccessfulOutcome, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SuccessfulOutcome")
	}
	bb.EnterComponent("SuccessfulOutcome")
	if err := X2apInternalSuccessfulOutcomeUnmarshalAPERFrom(v, bb); err != nil {
		return runtime.WrapDecodePath(err, "SuccessfulOutcome")
	}
	padding, err := aper.CaptureFinalBits(bb, "SuccessfulOutcome")
	if err != nil {
		return runtime.WrapDecodePath(err, "SuccessfulOutcome")
	}
	v.perPadding = padding.Padding()
	return nil
}
func X2apInternalSuccessfulOutcomeUnmarshalAPERFrom(v *SuccessfulOutcome, bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SuccessfulOutcome{}
	val_procedurecode, err := aper.DecodeIntegerAligned(bb, s00.X2apInternalInt64Ptr(0), s00.X2apInternalInt64Ptr(255), false)
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
	opaque_value, err := aper.DecodeOpaqueOpenTypeAligned(bb, s00.SuccessfulReason(v.ProcedureCode), aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "X2AP-PDU-Descriptions", Assignment: "Successful"}})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	opaque_value = opaque_value.WithPath("SuccessfulOutcome.Value")
	decoded_value, err := X2apInternalDecodeSuccessfulValue(v.ProcedureCode, opaque_value)
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
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "SuccessfulOutcome", v.receivedLocation, v.perPadding)
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

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *SuccessfulOutcome) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SuccessfulOutcome")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "SuccessfulOutcome")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APSuccessfulOutcome(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "SuccessfulOutcome")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "SuccessfulOutcome")
		}
		return X2apInternalSuccessfulOutcomeMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalSuccessfulOutcomeMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalSuccessfulOutcomeMarshalAPERWithPlan(v *SuccessfulOutcome, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalSuccessfulOutcomeMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SuccessfulOutcome")
}
func X2apInternalSuccessfulOutcomeMarshalAPERUnplanned(v *SuccessfulOutcome, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalSuccessfulOutcomeMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "SuccessfulOutcome")
}
func X2apInternalSuccessfulOutcomeMarshalAPERBudget(v *SuccessfulOutcome, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APSuccessfulOutcome(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalSuccessfulOutcomeMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalSuccessfulOutcomeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSuccessfulOutcomeMarshalAPERChanged(v *SuccessfulOutcome, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalSuccessfulOutcomeMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalSuccessfulOutcomeMarshalAPERPlanned(v *SuccessfulOutcome, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalSuccessfulOutcomeMarshalAPERTo(value, bb, fresh); err != nil {
		return nil, err
	}
	out, err := bb.CompleteBytesWithPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *SuccessfulOutcome) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SuccessfulOutcome")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded SuccessfulOutcome
	err := X2apInternalSuccessfulOutcomeUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APSuccessfulOutcome(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SuccessfulOutcome{}
		return report, aper.OperationError(err, "SuccessfulOutcome")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SuccessfulOutcome")
}
func X2apInternalCellActivationResponseFieldReceived(v *CellActivationResponse) *bool {
	return &v.received
}
func X2apInternalCellActivationResponseFieldReceivedAbsolute(v *CellActivationResponse) *bool {
	return &v.receivedAbsolute
}
func X2apInternalCellActivationResponseFieldReceivedBytes(v *CellActivationResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalENBConfigurationUpdateAcknowledgeFieldReceived(v *ENBConfigurationUpdateAcknowledge) *bool {
	return &v.received
}
func X2apInternalENBConfigurationUpdateAcknowledgeFieldReceivedAbsolute(v *ENBConfigurationUpdateAcknowledge) *bool {
	return &v.receivedAbsolute
}
func X2apInternalENBConfigurationUpdateAcknowledgeFieldReceivedBytes(v *ENBConfigurationUpdateAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalENDCCellActivationResponseFieldReceived(v *ENDCCellActivationResponse) *bool {
	return &v.received
}
func X2apInternalENDCCellActivationResponseFieldReceivedAbsolute(v *ENDCCellActivationResponse) *bool {
	return &v.receivedAbsolute
}
func X2apInternalENDCCellActivationResponseFieldReceivedBytes(v *ENDCCellActivationResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalENDCConfigurationUpdateAcknowledgeFieldReceived(v *ENDCConfigurationUpdateAcknowledge) *bool {
	return &v.received
}
func X2apInternalENDCConfigurationUpdateAcknowledgeFieldReceivedAbsolute(v *ENDCConfigurationUpdateAcknowledge) *bool {
	return &v.receivedAbsolute
}
func X2apInternalENDCConfigurationUpdateAcknowledgeFieldReceivedBytes(v *ENDCConfigurationUpdateAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalENDCPartialResetConfirmFieldReceived(v *ENDCPartialResetConfirm) *bool {
	return &v.received
}
func X2apInternalENDCPartialResetConfirmFieldReceivedAbsolute(v *ENDCPartialResetConfirm) *bool {
	return &v.receivedAbsolute
}
func X2apInternalENDCPartialResetConfirmFieldReceivedBytes(v *ENDCPartialResetConfirm) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalENDCResourceStatusResponseFieldReceived(v *ENDCResourceStatusResponse) *bool {
	return &v.received
}
func X2apInternalENDCResourceStatusResponseFieldReceivedAbsolute(v *ENDCResourceStatusResponse) *bool {
	return &v.receivedAbsolute
}
func X2apInternalENDCResourceStatusResponseFieldReceivedBytes(v *ENDCResourceStatusResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalENDCX2RemovalResponseFieldReceived(v *ENDCX2RemovalResponse) *bool {
	return &v.received
}
func X2apInternalENDCX2RemovalResponseFieldReceivedAbsolute(v *ENDCX2RemovalResponse) *bool {
	return &v.receivedAbsolute
}
func X2apInternalENDCX2RemovalResponseFieldReceivedBytes(v *ENDCX2RemovalResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalENDCX2SetupResponseFieldReceived(v *ENDCX2SetupResponse) *bool { return &v.received }
func X2apInternalENDCX2SetupResponseFieldReceivedAbsolute(v *ENDCX2SetupResponse) *bool {
	return &v.receivedAbsolute
}
func X2apInternalENDCX2SetupResponseFieldReceivedBytes(v *ENDCX2SetupResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalEUTRANRCellResourceCoordinationResponseFieldReceived(v *EUTRANRCellResourceCoordinationResponse) *bool {
	return &v.received
}
func X2apInternalEUTRANRCellResourceCoordinationResponseFieldReceivedAbsolute(v *EUTRANRCellResourceCoordinationResponse) *bool {
	return &v.receivedAbsolute
}
func X2apInternalEUTRANRCellResourceCoordinationResponseFieldReceivedBytes(v *EUTRANRCellResourceCoordinationResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalHandoverRequestAcknowledgeFieldReceived(v *HandoverRequestAcknowledge) *bool {
	return &v.received
}
func X2apInternalHandoverRequestAcknowledgeFieldReceivedAbsolute(v *HandoverRequestAcknowledge) *bool {
	return &v.receivedAbsolute
}
func X2apInternalHandoverRequestAcknowledgeFieldReceivedBytes(v *HandoverRequestAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalMobilityChangeAcknowledgeFieldReceived(v *MobilityChangeAcknowledge) *bool {
	return &v.received
}
func X2apInternalMobilityChangeAcknowledgeFieldReceivedAbsolute(v *MobilityChangeAcknowledge) *bool {
	return &v.receivedAbsolute
}
func X2apInternalMobilityChangeAcknowledgeFieldReceivedBytes(v *MobilityChangeAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalResetResponseFieldReceived(v *ResetResponse) *bool { return &v.received }
func X2apInternalResetResponseFieldReceivedAbsolute(v *ResetResponse) *bool {
	return &v.receivedAbsolute
}
func X2apInternalResetResponseFieldReceivedBytes(v *ResetResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalResourceStatusResponseFieldReceived(v *ResourceStatusResponse) *bool {
	return &v.received
}
func X2apInternalResourceStatusResponseFieldReceivedAbsolute(v *ResourceStatusResponse) *bool {
	return &v.receivedAbsolute
}
func X2apInternalResourceStatusResponseFieldReceivedBytes(v *ResourceStatusResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalRetrieveUEContextResponseFieldReceived(v *RetrieveUEContextResponse) *bool {
	return &v.received
}
func X2apInternalRetrieveUEContextResponseFieldReceivedAbsolute(v *RetrieveUEContextResponse) *bool {
	return &v.receivedAbsolute
}
func X2apInternalRetrieveUEContextResponseFieldReceivedBytes(v *RetrieveUEContextResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalSeNBAdditionRequestAcknowledgeFieldReceived(v *SeNBAdditionRequestAcknowledge) *bool {
	return &v.received
}
func X2apInternalSeNBAdditionRequestAcknowledgeFieldReceivedAbsolute(v *SeNBAdditionRequestAcknowledge) *bool {
	return &v.receivedAbsolute
}
func X2apInternalSeNBAdditionRequestAcknowledgeFieldReceivedBytes(v *SeNBAdditionRequestAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalSeNBModificationConfirmFieldReceived(v *SeNBModificationConfirm) *bool {
	return &v.received
}
func X2apInternalSeNBModificationConfirmFieldReceivedAbsolute(v *SeNBModificationConfirm) *bool {
	return &v.receivedAbsolute
}
func X2apInternalSeNBModificationConfirmFieldReceivedBytes(v *SeNBModificationConfirm) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalSeNBModificationRequestAcknowledgeFieldReceived(v *SeNBModificationRequestAcknowledge) *bool {
	return &v.received
}
func X2apInternalSeNBModificationRequestAcknowledgeFieldReceivedAbsolute(v *SeNBModificationRequestAcknowledge) *bool {
	return &v.receivedAbsolute
}
func X2apInternalSeNBModificationRequestAcknowledgeFieldReceivedBytes(v *SeNBModificationRequestAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalSeNBReleaseConfirmFieldReceived(v *SeNBReleaseConfirm) *bool { return &v.received }
func X2apInternalSeNBReleaseConfirmFieldReceivedAbsolute(v *SeNBReleaseConfirm) *bool {
	return &v.receivedAbsolute
}
func X2apInternalSeNBReleaseConfirmFieldReceivedBytes(v *SeNBReleaseConfirm) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalSgNBAdditionRequestAcknowledgeFieldReceived(v *SgNBAdditionRequestAcknowledge) *bool {
	return &v.received
}
func X2apInternalSgNBAdditionRequestAcknowledgeFieldReceivedAbsolute(v *SgNBAdditionRequestAcknowledge) *bool {
	return &v.receivedAbsolute
}
func X2apInternalSgNBAdditionRequestAcknowledgeFieldReceivedBytes(v *SgNBAdditionRequestAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalSgNBChangeConfirmFieldReceived(v *SgNBChangeConfirm) *bool { return &v.received }
func X2apInternalSgNBChangeConfirmFieldReceivedAbsolute(v *SgNBChangeConfirm) *bool {
	return &v.receivedAbsolute
}
func X2apInternalSgNBChangeConfirmFieldReceivedBytes(v *SgNBChangeConfirm) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalSgNBModificationConfirmFieldReceived(v *SgNBModificationConfirm) *bool {
	return &v.received
}
func X2apInternalSgNBModificationConfirmFieldReceivedAbsolute(v *SgNBModificationConfirm) *bool {
	return &v.receivedAbsolute
}
func X2apInternalSgNBModificationConfirmFieldReceivedBytes(v *SgNBModificationConfirm) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalSgNBModificationRequestAcknowledgeFieldReceived(v *SgNBModificationRequestAcknowledge) *bool {
	return &v.received
}
func X2apInternalSgNBModificationRequestAcknowledgeFieldReceivedAbsolute(v *SgNBModificationRequestAcknowledge) *bool {
	return &v.receivedAbsolute
}
func X2apInternalSgNBModificationRequestAcknowledgeFieldReceivedBytes(v *SgNBModificationRequestAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalSgNBReleaseConfirmFieldReceived(v *SgNBReleaseConfirm) *bool { return &v.received }
func X2apInternalSgNBReleaseConfirmFieldReceivedAbsolute(v *SgNBReleaseConfirm) *bool {
	return &v.receivedAbsolute
}
func X2apInternalSgNBReleaseConfirmFieldReceivedBytes(v *SgNBReleaseConfirm) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalSgNBReleaseRequestAcknowledgeFieldReceived(v *SgNBReleaseRequestAcknowledge) *bool {
	return &v.received
}
func X2apInternalSgNBReleaseRequestAcknowledgeFieldReceivedAbsolute(v *SgNBReleaseRequestAcknowledge) *bool {
	return &v.receivedAbsolute
}
func X2apInternalSgNBReleaseRequestAcknowledgeFieldReceivedBytes(v *SgNBReleaseRequestAcknowledge) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalSuccessfulValueFieldCode(v *SuccessfulValue) *s00.ProcedureCode { return &v.code }
func X2apInternalUERadioCapabilityIDMappingResponseFieldReceived(v *UERadioCapabilityIDMappingResponse) *bool {
	return &v.received
}
func X2apInternalUERadioCapabilityIDMappingResponseFieldReceivedAbsolute(v *UERadioCapabilityIDMappingResponse) *bool {
	return &v.receivedAbsolute
}
func X2apInternalUERadioCapabilityIDMappingResponseFieldReceivedBytes(v *UERadioCapabilityIDMappingResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalX2RemovalResponseFieldReceived(v *X2RemovalResponse) *bool { return &v.received }
func X2apInternalX2RemovalResponseFieldReceivedAbsolute(v *X2RemovalResponse) *bool {
	return &v.receivedAbsolute
}
func X2apInternalX2RemovalResponseFieldReceivedBytes(v *X2RemovalResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalX2SetupResponseFieldReceived(v *X2SetupResponse) *bool { return &v.received }
func X2apInternalX2SetupResponseFieldReceivedAbsolute(v *X2SetupResponse) *bool {
	return &v.receivedAbsolute
}
func X2apInternalX2SetupResponseFieldReceivedBytes(v *X2SetupResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func X2apInternalConstructT15SuccessfulValueF4codeF17bodyResetResponse(v0 s00.ProcedureCode, v1 *ResetResponse) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyResetResponse: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF19bodyX2SetupResponse(v0 s00.ProcedureCode, v1 *X2SetupResponse) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyX2SetupResponse: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF21bodySgNBChangeConfirm(v0 s00.ProcedureCode, v1 *SgNBChangeConfirm) SuccessfulValue {
	return SuccessfulValue{code: v0, bodySgNBChangeConfirm: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF21bodyX2RemovalResponse(v0 s00.ProcedureCode, v1 *X2RemovalResponse) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyX2RemovalResponse: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF22bodySeNBReleaseConfirm(v0 s00.ProcedureCode, v1 *SeNBReleaseConfirm) SuccessfulValue {
	return SuccessfulValue{code: v0, bodySeNBReleaseConfirm: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF22bodySgNBReleaseConfirm(v0 s00.ProcedureCode, v1 *SgNBReleaseConfirm) SuccessfulValue {
	return SuccessfulValue{code: v0, bodySgNBReleaseConfirm: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF23bodyENDCX2SetupResponse(v0 s00.ProcedureCode, v1 *ENDCX2SetupResponse) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyENDCX2SetupResponse: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF25bodyENDCX2RemovalResponse(v0 s00.ProcedureCode, v1 *ENDCX2RemovalResponse) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyENDCX2RemovalResponse: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF26bodyCellActivationResponse(v0 s00.ProcedureCode, v1 *CellActivationResponse) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyCellActivationResponse: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF26bodyResourceStatusResponse(v0 s00.ProcedureCode, v1 *ResourceStatusResponse) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyResourceStatusResponse: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF27bodyENDCPartialResetConfirm(v0 s00.ProcedureCode, v1 *ENDCPartialResetConfirm) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyENDCPartialResetConfirm: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF27bodySeNBModificationConfirm(v0 s00.ProcedureCode, v1 *SeNBModificationConfirm) SuccessfulValue {
	return SuccessfulValue{code: v0, bodySeNBModificationConfirm: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF27bodySgNBModificationConfirm(v0 s00.ProcedureCode, v1 *SgNBModificationConfirm) SuccessfulValue {
	return SuccessfulValue{code: v0, bodySgNBModificationConfirm: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF29bodyMobilityChangeAcknowledge(v0 s00.ProcedureCode, v1 *MobilityChangeAcknowledge) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyMobilityChangeAcknowledge: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF29bodyRetrieveUEContextResponse(v0 s00.ProcedureCode, v1 *RetrieveUEContextResponse) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyRetrieveUEContextResponse: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF30bodyENDCCellActivationResponse(v0 s00.ProcedureCode, v1 *ENDCCellActivationResponse) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyENDCCellActivationResponse: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF30bodyENDCResourceStatusResponse(v0 s00.ProcedureCode, v1 *ENDCResourceStatusResponse) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyENDCResourceStatusResponse: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF30bodyHandoverRequestAcknowledge(v0 s00.ProcedureCode, v1 *HandoverRequestAcknowledge) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyHandoverRequestAcknowledge: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF33bodySgNBReleaseRequestAcknowledge(v0 s00.ProcedureCode, v1 *SgNBReleaseRequestAcknowledge) SuccessfulValue {
	return SuccessfulValue{code: v0, bodySgNBReleaseRequestAcknowledge: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF34bodySeNBAdditionRequestAcknowledge(v0 s00.ProcedureCode, v1 *SeNBAdditionRequestAcknowledge) SuccessfulValue {
	return SuccessfulValue{code: v0, bodySeNBAdditionRequestAcknowledge: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF34bodySgNBAdditionRequestAcknowledge(v0 s00.ProcedureCode, v1 *SgNBAdditionRequestAcknowledge) SuccessfulValue {
	return SuccessfulValue{code: v0, bodySgNBAdditionRequestAcknowledge: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF37bodyENBConfigurationUpdateAcknowledge(v0 s00.ProcedureCode, v1 *ENBConfigurationUpdateAcknowledge) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyENBConfigurationUpdateAcknowledge: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF38bodyENDCConfigurationUpdateAcknowledge(v0 s00.ProcedureCode, v1 *ENDCConfigurationUpdateAcknowledge) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyENDCConfigurationUpdateAcknowledge: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF38bodySeNBModificationRequestAcknowledge(v0 s00.ProcedureCode, v1 *SeNBModificationRequestAcknowledge) SuccessfulValue {
	return SuccessfulValue{code: v0, bodySeNBModificationRequestAcknowledge: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF38bodySgNBModificationRequestAcknowledge(v0 s00.ProcedureCode, v1 *SgNBModificationRequestAcknowledge) SuccessfulValue {
	return SuccessfulValue{code: v0, bodySgNBModificationRequestAcknowledge: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF38bodyUERadioCapabilityIDMappingResponse(v0 s00.ProcedureCode, v1 *UERadioCapabilityIDMappingResponse) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyUERadioCapabilityIDMappingResponse: v1}
}
func X2apInternalConstructT15SuccessfulValueF4codeF43bodyEUTRANRCellResourceCoordinationResponse(v0 s00.ProcedureCode, v1 *EUTRANRCellResourceCoordinationResponse) SuccessfulValue {
	return SuccessfulValue{code: v0, bodyEUTRANRCellResourceCoordinationResponse: v1}
}
func X2apInternalConstructT30ResetResponseSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*ResetResponse, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*ResetResponse, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (ResetResponse, error), v4 func(ResetResponse) SuccessfulValue, v5 func(ResetResponse, aper.DecodeState) (ResetResponse, aper.Snapshot), v6 func(ResetResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) ResetResponseSuccessfulBinding {
	return ResetResponseSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT32X2SetupResponseSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*X2SetupResponse, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*X2SetupResponse, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (X2SetupResponse, error), v4 func(X2SetupResponse) SuccessfulValue, v5 func(X2SetupResponse, aper.DecodeState) (X2SetupResponse, aper.Snapshot), v6 func(X2SetupResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) X2SetupResponseSuccessfulBinding {
	return X2SetupResponseSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT34SgNBChangeConfirmSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*SgNBChangeConfirm, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*SgNBChangeConfirm, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (SgNBChangeConfirm, error), v4 func(SgNBChangeConfirm) SuccessfulValue, v5 func(SgNBChangeConfirm, aper.DecodeState) (SgNBChangeConfirm, aper.Snapshot), v6 func(SgNBChangeConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) SgNBChangeConfirmSuccessfulBinding {
	return SgNBChangeConfirmSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT34X2RemovalResponseSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*X2RemovalResponse, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*X2RemovalResponse, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (X2RemovalResponse, error), v4 func(X2RemovalResponse) SuccessfulValue, v5 func(X2RemovalResponse, aper.DecodeState) (X2RemovalResponse, aper.Snapshot), v6 func(X2RemovalResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) X2RemovalResponseSuccessfulBinding {
	return X2RemovalResponseSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT35SeNBReleaseConfirmSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*SeNBReleaseConfirm, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*SeNBReleaseConfirm, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (SeNBReleaseConfirm, error), v4 func(SeNBReleaseConfirm) SuccessfulValue, v5 func(SeNBReleaseConfirm, aper.DecodeState) (SeNBReleaseConfirm, aper.Snapshot), v6 func(SeNBReleaseConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) SeNBReleaseConfirmSuccessfulBinding {
	return SeNBReleaseConfirmSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT35SgNBReleaseConfirmSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*SgNBReleaseConfirm, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*SgNBReleaseConfirm, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (SgNBReleaseConfirm, error), v4 func(SgNBReleaseConfirm) SuccessfulValue, v5 func(SgNBReleaseConfirm, aper.DecodeState) (SgNBReleaseConfirm, aper.Snapshot), v6 func(SgNBReleaseConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) SgNBReleaseConfirmSuccessfulBinding {
	return SgNBReleaseConfirmSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT36ENDCX2SetupResponseSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*ENDCX2SetupResponse, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*ENDCX2SetupResponse, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (ENDCX2SetupResponse, error), v4 func(ENDCX2SetupResponse) SuccessfulValue, v5 func(ENDCX2SetupResponse, aper.DecodeState) (ENDCX2SetupResponse, aper.Snapshot), v6 func(ENDCX2SetupResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) ENDCX2SetupResponseSuccessfulBinding {
	return ENDCX2SetupResponseSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT38ENDCX2RemovalResponseSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*ENDCX2RemovalResponse, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*ENDCX2RemovalResponse, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (ENDCX2RemovalResponse, error), v4 func(ENDCX2RemovalResponse) SuccessfulValue, v5 func(ENDCX2RemovalResponse, aper.DecodeState) (ENDCX2RemovalResponse, aper.Snapshot), v6 func(ENDCX2RemovalResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) ENDCX2RemovalResponseSuccessfulBinding {
	return ENDCX2RemovalResponseSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT39CellActivationResponseSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*CellActivationResponse, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*CellActivationResponse, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (CellActivationResponse, error), v4 func(CellActivationResponse) SuccessfulValue, v5 func(CellActivationResponse, aper.DecodeState) (CellActivationResponse, aper.Snapshot), v6 func(CellActivationResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) CellActivationResponseSuccessfulBinding {
	return CellActivationResponseSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT39ResourceStatusResponseSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*ResourceStatusResponse, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*ResourceStatusResponse, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (ResourceStatusResponse, error), v4 func(ResourceStatusResponse) SuccessfulValue, v5 func(ResourceStatusResponse, aper.DecodeState) (ResourceStatusResponse, aper.Snapshot), v6 func(ResourceStatusResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) ResourceStatusResponseSuccessfulBinding {
	return ResourceStatusResponseSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT40ENDCPartialResetConfirmSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*ENDCPartialResetConfirm, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*ENDCPartialResetConfirm, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (ENDCPartialResetConfirm, error), v4 func(ENDCPartialResetConfirm) SuccessfulValue, v5 func(ENDCPartialResetConfirm, aper.DecodeState) (ENDCPartialResetConfirm, aper.Snapshot), v6 func(ENDCPartialResetConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) ENDCPartialResetConfirmSuccessfulBinding {
	return ENDCPartialResetConfirmSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT40SeNBModificationConfirmSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*SeNBModificationConfirm, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*SeNBModificationConfirm, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (SeNBModificationConfirm, error), v4 func(SeNBModificationConfirm) SuccessfulValue, v5 func(SeNBModificationConfirm, aper.DecodeState) (SeNBModificationConfirm, aper.Snapshot), v6 func(SeNBModificationConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) SeNBModificationConfirmSuccessfulBinding {
	return SeNBModificationConfirmSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT40SgNBModificationConfirmSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*SgNBModificationConfirm, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*SgNBModificationConfirm, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (SgNBModificationConfirm, error), v4 func(SgNBModificationConfirm) SuccessfulValue, v5 func(SgNBModificationConfirm, aper.DecodeState) (SgNBModificationConfirm, aper.Snapshot), v6 func(SgNBModificationConfirm, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) SgNBModificationConfirmSuccessfulBinding {
	return SgNBModificationConfirmSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT42MobilityChangeAcknowledgeSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*MobilityChangeAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*MobilityChangeAcknowledge, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (MobilityChangeAcknowledge, error), v4 func(MobilityChangeAcknowledge) SuccessfulValue, v5 func(MobilityChangeAcknowledge, aper.DecodeState) (MobilityChangeAcknowledge, aper.Snapshot), v6 func(MobilityChangeAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) MobilityChangeAcknowledgeSuccessfulBinding {
	return MobilityChangeAcknowledgeSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT42RetrieveUEContextResponseSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*RetrieveUEContextResponse, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*RetrieveUEContextResponse, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (RetrieveUEContextResponse, error), v4 func(RetrieveUEContextResponse) SuccessfulValue, v5 func(RetrieveUEContextResponse, aper.DecodeState) (RetrieveUEContextResponse, aper.Snapshot), v6 func(RetrieveUEContextResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) RetrieveUEContextResponseSuccessfulBinding {
	return RetrieveUEContextResponseSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT43ENDCCellActivationResponseSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*ENDCCellActivationResponse, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*ENDCCellActivationResponse, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (ENDCCellActivationResponse, error), v4 func(ENDCCellActivationResponse) SuccessfulValue, v5 func(ENDCCellActivationResponse, aper.DecodeState) (ENDCCellActivationResponse, aper.Snapshot), v6 func(ENDCCellActivationResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) ENDCCellActivationResponseSuccessfulBinding {
	return ENDCCellActivationResponseSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT43ENDCResourceStatusResponseSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*ENDCResourceStatusResponse, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*ENDCResourceStatusResponse, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (ENDCResourceStatusResponse, error), v4 func(ENDCResourceStatusResponse) SuccessfulValue, v5 func(ENDCResourceStatusResponse, aper.DecodeState) (ENDCResourceStatusResponse, aper.Snapshot), v6 func(ENDCResourceStatusResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) ENDCResourceStatusResponseSuccessfulBinding {
	return ENDCResourceStatusResponseSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT43HandoverRequestAcknowledgeSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*HandoverRequestAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*HandoverRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (HandoverRequestAcknowledge, error), v4 func(HandoverRequestAcknowledge) SuccessfulValue, v5 func(HandoverRequestAcknowledge, aper.DecodeState) (HandoverRequestAcknowledge, aper.Snapshot), v6 func(HandoverRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) HandoverRequestAcknowledgeSuccessfulBinding {
	return HandoverRequestAcknowledgeSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT46SgNBReleaseRequestAcknowledgeSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*SgNBReleaseRequestAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*SgNBReleaseRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (SgNBReleaseRequestAcknowledge, error), v4 func(SgNBReleaseRequestAcknowledge) SuccessfulValue, v5 func(SgNBReleaseRequestAcknowledge, aper.DecodeState) (SgNBReleaseRequestAcknowledge, aper.Snapshot), v6 func(SgNBReleaseRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) SgNBReleaseRequestAcknowledgeSuccessfulBinding {
	return SgNBReleaseRequestAcknowledgeSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT47SeNBAdditionRequestAcknowledgeSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*SeNBAdditionRequestAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*SeNBAdditionRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (SeNBAdditionRequestAcknowledge, error), v4 func(SeNBAdditionRequestAcknowledge) SuccessfulValue, v5 func(SeNBAdditionRequestAcknowledge, aper.DecodeState) (SeNBAdditionRequestAcknowledge, aper.Snapshot), v6 func(SeNBAdditionRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) SeNBAdditionRequestAcknowledgeSuccessfulBinding {
	return SeNBAdditionRequestAcknowledgeSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT47SgNBAdditionRequestAcknowledgeSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*SgNBAdditionRequestAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*SgNBAdditionRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (SgNBAdditionRequestAcknowledge, error), v4 func(SgNBAdditionRequestAcknowledge) SuccessfulValue, v5 func(SgNBAdditionRequestAcknowledge, aper.DecodeState) (SgNBAdditionRequestAcknowledge, aper.Snapshot), v6 func(SgNBAdditionRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) SgNBAdditionRequestAcknowledgeSuccessfulBinding {
	return SgNBAdditionRequestAcknowledgeSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT50ENBConfigurationUpdateAcknowledgeSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*ENBConfigurationUpdateAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*ENBConfigurationUpdateAcknowledge, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (ENBConfigurationUpdateAcknowledge, error), v4 func(ENBConfigurationUpdateAcknowledge) SuccessfulValue, v5 func(ENBConfigurationUpdateAcknowledge, aper.DecodeState) (ENBConfigurationUpdateAcknowledge, aper.Snapshot), v6 func(ENBConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) ENBConfigurationUpdateAcknowledgeSuccessfulBinding {
	return ENBConfigurationUpdateAcknowledgeSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT51ENDCConfigurationUpdateAcknowledgeSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*ENDCConfigurationUpdateAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*ENDCConfigurationUpdateAcknowledge, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (ENDCConfigurationUpdateAcknowledge, error), v4 func(ENDCConfigurationUpdateAcknowledge) SuccessfulValue, v5 func(ENDCConfigurationUpdateAcknowledge, aper.DecodeState) (ENDCConfigurationUpdateAcknowledge, aper.Snapshot), v6 func(ENDCConfigurationUpdateAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) ENDCConfigurationUpdateAcknowledgeSuccessfulBinding {
	return ENDCConfigurationUpdateAcknowledgeSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT51SeNBModificationRequestAcknowledgeSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*SeNBModificationRequestAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*SeNBModificationRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (SeNBModificationRequestAcknowledge, error), v4 func(SeNBModificationRequestAcknowledge) SuccessfulValue, v5 func(SeNBModificationRequestAcknowledge, aper.DecodeState) (SeNBModificationRequestAcknowledge, aper.Snapshot), v6 func(SeNBModificationRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) SeNBModificationRequestAcknowledgeSuccessfulBinding {
	return SeNBModificationRequestAcknowledgeSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT51SgNBModificationRequestAcknowledgeSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*SgNBModificationRequestAcknowledge, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*SgNBModificationRequestAcknowledge, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (SgNBModificationRequestAcknowledge, error), v4 func(SgNBModificationRequestAcknowledge) SuccessfulValue, v5 func(SgNBModificationRequestAcknowledge, aper.DecodeState) (SgNBModificationRequestAcknowledge, aper.Snapshot), v6 func(SgNBModificationRequestAcknowledge, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) SgNBModificationRequestAcknowledgeSuccessfulBinding {
	return SgNBModificationRequestAcknowledgeSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT51UERadioCapabilityIDMappingResponseSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*UERadioCapabilityIDMappingResponse, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*UERadioCapabilityIDMappingResponse, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponse, error), v4 func(UERadioCapabilityIDMappingResponse) SuccessfulValue, v5 func(UERadioCapabilityIDMappingResponse, aper.DecodeState) (UERadioCapabilityIDMappingResponse, aper.Snapshot), v6 func(UERadioCapabilityIDMappingResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) UERadioCapabilityIDMappingResponseSuccessfulBinding {
	return UERadioCapabilityIDMappingResponseSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}
func X2apInternalConstructT56EUTRANRCellResourceCoordinationResponseSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(v0 s00.ProcedureInfo, v1 func(*EUTRANRCellResourceCoordinationResponse, *aper.DecodeBudget) (s12.ValidationReport, error), v2 func(*EUTRANRCellResourceCoordinationResponse, bool, *aper.DecodeBudget) ([]byte, error), v3 func([]byte, aper.DecodeState) (EUTRANRCellResourceCoordinationResponse, error), v4 func(EUTRANRCellResourceCoordinationResponse) SuccessfulValue, v5 func(EUTRANRCellResourceCoordinationResponse, aper.DecodeState) (EUTRANRCellResourceCoordinationResponse, aper.Snapshot), v6 func(EUTRANRCellResourceCoordinationResponse, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan, v7 s00.X2apInternalCodecContext) EUTRANRCellResourceCoordinationResponseSuccessfulBinding {
	return EUTRANRCellResourceCoordinationResponseSuccessfulBinding{info: v0, validate: v1, encode: v2, decode: v3, inject: v4, capture: v5, compare: v6, context: v7}
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *SuccessfulValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.code {
	case s00.ProcedureCode(0):
		if v.bodyHandoverRequestAcknowledge != nil {
			return v.bodyHandoverRequestAcknowledge, true
		}
	case s00.ProcedureCode(12):
		if v.bodyMobilityChangeAcknowledge != nil {
			return v.bodyMobilityChangeAcknowledge, true
		}
	case s00.ProcedureCode(15):
		if v.bodyCellActivationResponse != nil {
			return v.bodyCellActivationResponse, true
		}
	case s00.ProcedureCode(18):
		if v.bodyX2RemovalResponse != nil {
			return v.bodyX2RemovalResponse, true
		}
	case s00.ProcedureCode(19):
		if v.bodySeNBAdditionRequestAcknowledge != nil {
			return v.bodySeNBAdditionRequestAcknowledge, true
		}
	case s00.ProcedureCode(21):
		if v.bodySeNBModificationRequestAcknowledge != nil {
			return v.bodySeNBModificationRequestAcknowledge, true
		}
	case s00.ProcedureCode(22):
		if v.bodySeNBModificationConfirm != nil {
			return v.bodySeNBModificationConfirm, true
		}
	case s00.ProcedureCode(24):
		if v.bodySeNBReleaseConfirm != nil {
			return v.bodySeNBReleaseConfirm, true
		}
	case s00.ProcedureCode(26):
		if v.bodyRetrieveUEContextResponse != nil {
			return v.bodyRetrieveUEContextResponse, true
		}
	case s00.ProcedureCode(27):
		if v.bodySgNBAdditionRequestAcknowledge != nil {
			return v.bodySgNBAdditionRequestAcknowledge, true
		}
	case s00.ProcedureCode(29):
		if v.bodySgNBModificationRequestAcknowledge != nil {
			return v.bodySgNBModificationRequestAcknowledge, true
		}
	case s00.ProcedureCode(30):
		if v.bodySgNBModificationConfirm != nil {
			return v.bodySgNBModificationConfirm, true
		}
	case s00.ProcedureCode(31):
		if v.bodySgNBReleaseRequestAcknowledge != nil {
			return v.bodySgNBReleaseRequestAcknowledge, true
		}
	case s00.ProcedureCode(32):
		if v.bodySgNBReleaseConfirm != nil {
			return v.bodySgNBReleaseConfirm, true
		}
	case s00.ProcedureCode(34):
		if v.bodySgNBChangeConfirm != nil {
			return v.bodySgNBChangeConfirm, true
		}
	case s00.ProcedureCode(36):
		if v.bodyENDCX2SetupResponse != nil {
			return v.bodyENDCX2SetupResponse, true
		}
	case s00.ProcedureCode(37):
		if v.bodyENDCConfigurationUpdateAcknowledge != nil {
			return v.bodyENDCConfigurationUpdateAcknowledge, true
		}
	case s00.ProcedureCode(39):
		if v.bodyENDCCellActivationResponse != nil {
			return v.bodyENDCCellActivationResponse, true
		}
	case s00.ProcedureCode(40):
		if v.bodyENDCPartialResetConfirm != nil {
			return v.bodyENDCPartialResetConfirm, true
		}
	case s00.ProcedureCode(41):
		if v.bodyEUTRANRCellResourceCoordinationResponse != nil {
			return v.bodyEUTRANRCellResourceCoordinationResponse, true
		}
	case s00.ProcedureCode(43):
		if v.bodyENDCX2RemovalResponse != nil {
			return v.bodyENDCX2RemovalResponse, true
		}
	case s00.ProcedureCode(54):
		if v.bodyENDCResourceStatusResponse != nil {
			return v.bodyENDCResourceStatusResponse, true
		}
	case s00.ProcedureCode(56):
		if v.bodyUERadioCapabilityIDMappingResponse != nil {
			return v.bodyUERadioCapabilityIDMappingResponse, true
		}
	case s00.ProcedureCode(6):
		if v.bodyX2SetupResponse != nil {
			return v.bodyX2SetupResponse, true
		}
	case s00.ProcedureCode(7):
		if v.bodyResetResponse != nil {
			return v.bodyResetResponse, true
		}
	case s00.ProcedureCode(8):
		if v.bodyENBConfigurationUpdateAcknowledge != nil {
			return v.bodyENBConfigurationUpdateAcknowledge, true
		}
	case s00.ProcedureCode(9):
		if v.bodyResourceStatusResponse != nil {
			return v.bodyResourceStatusResponse, true
		}
	}
	return nil, false
}
